/**
 * Copyright (c) FOM-Nikhef 2015-
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 *
 *  Authors:
 *  2015-
 *     Mischa Sall\'e <msalle@nikhef.nl>
 *     NIKHEF Amsterdam, the Netherlands
 *     <grid-mw-security@nikhef.nl>
 *
 */

/**
 * NOTES: lcmaps-verify-proxy checks payload chain->if one longer than pilot:
 * pilot also checked. Only check whether is indeed only one longer. So check
 * cert by cert until bottom of stack. Probably don't need to rebase on a CA.
 * Still need external check that pilot may do this: on GUMS can check pilot DN
 * is allowed to make pilot proxies (has role pilot) */

#include <openssl/x509.h>
#include <string.h>

#include "lcmaps_plugins_pilot_sub_proxy_config.h"

#include <lcmaps/lcmaps_defines.h>
#include <lcmaps/lcmaps_arguments.h>
#include <lcmaps/lcmaps_log.h>

#if defined(HAVE_LCMAPS_LCMAPS_PLUGIN_PROTOTYPES_H)
#   include <lcmaps/lcmaps_plugin_prototypes.h>
#else
#   include "lcmaps_plugin_prototypes.h"
#endif

#include "lcmaps_pilot_sub_proxy_utils.h"


/************************************************************************
 * defines
 ************************************************************************/

#define PLUGIN_PREFIX	"lcmaps_pilot_sub_proxy"

#define PLUGIN_RUN	0   /* full run mode */
#define PLUGIN_VERIFY	1   /* verify-only mode */


/************************************************************************
 * global variables
 ************************************************************************/

/** Whether to only register DN or also FQANs, default yes */
static int add_pilot_fqans=1;

/** Whether to require proxies are limited, default yes */
static int require_limited=1;

/** When set, the FQAN pattern must match one of the FQANs */
static char *fqan_pattern=NULL;

/** Lock type to use for reading the X509_USER_PROXY */
static lock_type_t lock_type=LOCK_NOLOCK;


/************************************************************************
 * private prototypes
 ************************************************************************/

/* called by plugin_run() and plugin_verify() */
static int plugin_run_or_verify(int argc, lcmaps_argument_t *argv,
				int lcmaps_mode);


/************************************************************************
 * public functions
 ************************************************************************/

/**
 * Initialize function for plugin
 */
int plugin_initialize(int argc, char **argv) {
    const char * logstr = PLUGIN_PREFIX"-plugin_initialize()";
    int i;

    /* Log commandline parameters on debug */
    lcmaps_log(LOG_DEBUG,"%s: passed arguments:\n",logstr);
    for (i=0; i < argc; i++)
	lcmaps_log(LOG_DEBUG,"%s: arg %d is %s\n", logstr, i, argv[i]);

    /* Parse arguments, argv[0] = name of plugin, so start with i = 1 */
    for (i = 1; i < argc; i++) {
	if (strcmp(argv[i], "--add-pilot-fqans") == 0)
	{
	    if (argv[i + 1] == NULL)	{
		lcmaps_log(LOG_ERR,
		    "%s: option %s needs to be followed by 'yes' or 'no'\n",
		    logstr, argv[i]);
		return LCMAPS_MOD_FAIL;
	    }
	    if (strcmp(argv[i+1],"yes") == 0)  {
		lcmaps_log(LOG_DEBUG,
		    "%s: will add FQANs from pilot when available\n", logstr);
		add_pilot_fqans=1;
	    } else if (strcmp(argv[i+1],"no") == 0)  {
		lcmaps_log(LOG_DEBUG,
		    "%s: will NOT add FQANs from pilot\n", logstr);
		add_pilot_fqans=0;
	    } else {
		lcmaps_log(LOG_ERR,
		    "%s: option %s should have value 'yes' or 'no', not '%s'\n",
		    logstr, argv[i], argv[i]);
		return LCMAPS_MOD_FAIL;
	    }
	    i++;
	}
	else if (strcmp(argv[i], "--require-limited") == 0)
	{
	    if (argv[i + 1] == NULL)	{
		lcmaps_log(LOG_ERR,
		    "%s: option %s needs to be followed by 'yes' or 'no'\n",
		    logstr, argv[i]);
		return LCMAPS_MOD_FAIL;
	    }
	    if (strcmp(argv[i+1],"yes") == 0)  {
		lcmaps_log(LOG_DEBUG,
		    "%s: require proxies to be limited\n", logstr);
		require_limited=1;
	    } else if (strcmp(argv[i+1],"no") == 0)  {
		lcmaps_log(LOG_DEBUG,
		    "%s: do NOT require proxies to be limited\n", logstr);
		require_limited=0;
	    } else {
		lcmaps_log(LOG_ERR,
		    "%s: option %s should have value 'yes' or 'no', not '%s'\n",
		    logstr, argv[i], argv[i]);
		return LCMAPS_MOD_FAIL;
	    }
	    i++;
	}
	else if (strcmp(argv[i], "--match-fqan") == 0)
	{
	    if (argv[i + 1] == NULL)	{
		lcmaps_log(LOG_ERR,
		    "%s: option %s needs to be followed by FQAN pattern\n",
		    logstr, argv[i]);
		return LCMAPS_MOD_FAIL;
	    }
	    if (argv[i + 1][0]!='\0')
		fqan_pattern=argv[i + 1];
	    i++;
	}
	else if (strcmp(argv[i], "--lock-type") == 0)
	{
	    if (argv[i + 1] == NULL)	{
		lcmaps_log(LOG_ERR,
		    "%s: option %s needs to be followed by valid lock type\n",
		    logstr, argv[i]);
		return LCMAPS_MOD_FAIL;
	    }
	    if (strcmp(argv[i+1], "none") == 0)	{
		lcmaps_log(LOG_INFO,
			"%s: not using locking for reading X509_USER_PROXY\n",
			logstr);
		lock_type=LOCK_NOLOCK;
	    } else if (strcmp(argv[i+1], "fcntl") == 0) {
		lcmaps_log(LOG_INFO,
			"%s: using fcntl locking for reading X509_USER_PROXY\n",
			logstr);
		lock_type=LOCK_FCNTL;
	    } else if (strcmp(argv[i+1], "flock") == 0)	{
		lcmaps_log(LOG_INFO,
			"%s: using flock locking for reading X509_USER_PROXY\n",
			logstr);
		lock_type=LOCK_FLOCK;
	    } else    {
		lcmaps_log(LOG_ERR, "%s: unknown lock_type \"%s\"\n",
			logstr, argv[i+1]);
		return LCMAPS_MOD_FAIL;
	    }
	    i++;
	}
	else
	{
            lcmaps_log(LOG_ERR,
		    "%s: Unknown argument for plugin: %s (failure)\n",
		    logstr, argv[i]);
            return LCMAPS_MOD_FAIL;
        }
    }

    return LCMAPS_MOD_SUCCESS;
}

/**
 * Introspect function for plugin, defines which lcmaps framework data is made
 * available as commandline options for the plugin_run.
 */
int plugin_introspect(int *argc, lcmaps_argument_t **argv) {
    const char * logstr = PLUGIN_PREFIX"-plugin_introspect()";
    static lcmaps_argument_t argList[] = {
	{"user_dn"    ,"char *"          , 1,NULL},
	{"nfqan"      ,"int"             , 0,NULL},
	{"fqan_list"  ,"char **"         , 0,NULL},
	{"px509_chain","STACK_OF(X509) *", 0,NULL},
	{"pem_string" ,"char *"          , 0,NULL},
	{NULL         ,NULL              ,-1,NULL}
    };

    lcmaps_log(LOG_DEBUG,"%s: introspecting\n", logstr);

    *argv = argList;
    *argc = lcmaps_cntArgs(argList);
    lcmaps_log(LOG_DEBUG,"%s: address first argument: %p\n",
	    logstr, (void*)argList);

    return LCMAPS_MOD_SUCCESS;
}

/**
 * run function for plugin, wrapper around plugin_run_or_verify() with
 * PLUGIN_RUN mode
 */
int plugin_run(int argc, lcmaps_argument_t *argv) {
    return plugin_run_or_verify(argc, argv, PLUGIN_RUN);
}

/**
 * run function for plugin, wrapper around plugin_run_or_verify() with
 * PLUGIN_VERIFY mode
 */
int plugin_verify(int argc, lcmaps_argument_t *argv) {
    return plugin_run_or_verify(argc, argv, PLUGIN_VERIFY);
}

/**
 * terminate plugin, frees used memory.
 * return LCMAPS_MOD_SUCCESS
 */
int plugin_terminate(void) {
    const char * logstr = PLUGIN_PREFIX"-plugin_terminate()";

    lcmaps_log(LOG_DEBUG,"%s: terminating\n", logstr);

    return LCMAPS_MOD_SUCCESS;
}



/************************************************************************
 * private functions
 ************************************************************************/

/**
 * Actual run/verify function. Called by both plugin_run and plugin_verify
 * with different lcmaps_mode.
 */
static int plugin_run_or_verify(int argc, lcmaps_argument_t *argv,
				int lcmaps_mode) {
    const char *        logstr       = NULL;
    STACK_OF(X509)*	pilot_chain  = NULL;
    STACK_OF(X509)*	payload_chain= NULL;
    X509 *		pilot_cert   = NULL;
    X509 *		payload_cert = NULL;
    int                 nfqans       = -1;
    char **             fqans        = NULL;

    /* Set suitable logstr */
    if (lcmaps_mode == PLUGIN_RUN)
        logstr = PLUGIN_PREFIX"-plugin_run()";
    else if (lcmaps_mode == PLUGIN_VERIFY)
        logstr = PLUGIN_PREFIX"-plugin_verify()";
    else {
        lcmaps_log(LOG_ERR, PLUGIN_PREFIX"-plugin_run_or_verify(): "
		"attempt to run plugin in invalid mode: %d\n", lcmaps_mode);
        goto fail_plugin;
    }

    /* Get X509_USER_PROXY */
    if (psp_get_pilot_proxy(&pilot_chain, lock_type))
	goto fail_plugin;

    /* Get payload proxy (typically PEM string)	*/
    if (psp_get_payload_proxy(&payload_chain, argc, argv))
	goto fail_plugin;

    /* Get FQANs when needed */
    if (add_pilot_fqans || fqan_pattern)    {
	if (psp_get_fqans(&nfqans, &fqans, argc, argv))
	    goto fail_plugin;
    }

    /* Get leaf proxies */
    pilot_cert=sk_X509_value(pilot_chain,0);
    payload_cert=sk_X509_value(payload_chain,0);
    if (pilot_cert==NULL || payload_cert==NULL)	{
	lcmaps_log(LOG_WARNING, "%s: cannot get leaf proxy certs from chains\n",
		logstr);
	goto fail_plugin;
    }

    /* Check whether chains are valid RFC proxies */
    if (psp_proxy_is_rfc(pilot_cert)==0)    {
	lcmaps_log(LOG_WARNING,
	    "%s: pilot proxy is not RFC compliant\n", logstr);
	goto fail_plugin;
    }
    if (psp_proxy_is_rfc(payload_cert)==0)	{
	lcmaps_log(LOG_WARNING,
	    "%s: payload proxy is not RFC compliant\n", logstr);
	goto fail_plugin;
    }

    /* Check whether either proxy is not LIMITED */
    if (require_limited)    {
	if (psp_proxy_is_limited(pilot_cert)==0)	{
	    lcmaps_log(LOG_WARNING,
		"%s: pilot proxy is not a Limited proxy\n", logstr);
	    goto fail_plugin;
	}
	if (psp_proxy_is_limited(payload_cert)==0)	{
	    lcmaps_log(LOG_WARNING,
		"%s: payload proxy is not a Limited proxy\n", logstr);
	    goto fail_plugin;
	}
    }

    /* Check pattern */
    if (fqan_pattern && (psp_match_fqan(nfqans, fqans, fqan_pattern)==0))   {
	lcmaps_log(LOG_WARNING,
	    "%s: proxy does not contain required FQAN(-pattern) %s\n",
	    logstr, fqan_pattern);
	goto fail_plugin;
    }

    /* Do actual verification */
    if (psp_verify_proxy_signature(payload_cert, pilot_cert))
	goto fail_plugin;
    
    /* Store the DN of the payload cert as user_dn */
    if (psp_store_proxy_dn(payload_cert))
	goto fail_plugin;

    /* Store the FQANs of the proxy when add_pilot_fqans==1 */
    if (add_pilot_fqans && psp_store_fqans(nfqans, fqans))
	goto fail_plugin;
   
    /* Cleanup chain memory */
    psp_cleanup_chains(pilot_chain, payload_chain);

    lcmaps_log(LOG_INFO,"%s: %s plugin succeeded\n", logstr, PLUGIN_PREFIX);

    return LCMAPS_MOD_SUCCESS;

fail_plugin:
    /* Cleanup chain memory */
    psp_cleanup_chains(pilot_chain, payload_chain);

    lcmaps_log(LOG_INFO,"%s: %s plugin failed\n", logstr, PLUGIN_PREFIX);

    return LCMAPS_MOD_FAIL;
}
