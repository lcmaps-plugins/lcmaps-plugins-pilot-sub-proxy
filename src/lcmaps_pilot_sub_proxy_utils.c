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

/* needed for e.g. seteuid, also for usleep */
#define _XOPEN_SOURCE	600

#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h> /* proxy info */

#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <fnmatch.h>

#include <lcmaps/lcmaps_arguments.h>
#include <lcmaps/lcmaps_cred_data.h>
#include <lcmaps/lcmaps_log.h>

#include "lcmaps_pilot_sub_proxy_utils.h"


/************************************************************************
 * Defines
 ************************************************************************/

#define OBJ_BUF_SIZE        80	/* bufsize for OID text */

#define OID_RFC_PROXY       "1.3.6.1.5.5.7.1.14"  /* OID for RFC3820 proxy */
#define OID_LIMITED_PROXY   "1.3.6.1.4.1.3536.1.1.1.9"  /* OID limited proxy */

/** Following are locking flags used by filelock() */
#define LCK_NOLOCK  1<<0    /* no locking */
#define LCK_FCNTL   1<<1    /* use fcntl() locking */
#define LCK_FLOCK   1<<2    /* use flock() locking */
#define LCK_READ    1<<0    /* set/unset read lock */
#define LCK_WRITE   1<<1    /* set/unset write lock */
#define LCK_UNLOCK  1<<2    /* unset lock */

/************************************************************************
 * Global variables
 ************************************************************************/

static int payload_chain_needs_cleaning=0;


/************************************************************************
 * Static prototypes
 ************************************************************************/

/* Convert PEM string to stack of X509 certificates and private key. Stack and
 * key need to be cleaned up afterwards. When pkey==NULL, no private key is
 * obtained.
 * \return 0 on success or -1 on error */
static int pem_string_to_x509_chain(STACK_OF(X509) **certstack, EVP_PKEY **pkey,
				    char *certstring);

/* Empty verify callback for reading in the password-less private key
 * \return 0 */
static int empty_callback(char *buf, int buf_size, int verify, void *cb_tmp);

/* Drops privilege to an unprivileged account. Can be raised using \see
 * raise_priv
 * \return 0 when successful, or the return code of set[ug]id() on error. */
static int priv_drop(uid_t unpriv_uid,gid_t unpriv_gid);

/* Tries to raise privilege level back to euid/egid when dropped previously
 * using \see priv_drop
 * \return -1 when fails or impossible (neither euid or real uid is root), 0
 * upon success. */
static int raise_priv(uid_t euid, gid_t egid);

/* Reads proxy from *path . It tries to drop privilege to real-uid/real-gid when
 * euid==0 and uid!=0. Space needed will be malloc-ed.
 * Upon successful completion proxy contains the contents of path.
 * \return 0 on success or value < 0 indicating the type of error. */
static int read_proxy(const char *path, int lock_type, char **proxy);


/************************************************************************
 * Public functions
 ************************************************************************/

/**
 * Retrieves the X509_USER_PROXY certificate stack.
 * \return 0 on success, -1 on error.
 */
int psp_get_pilot_proxy(STACK_OF(X509) **certstack, lock_type_t lock_type)  {
    char *proxy=getenv("X509_USER_PROXY");
    char *pem_buf=NULL;
    STACK_OF(X509)*chain=NULL;
    EVP_PKEY *privkey=NULL;
    int rc;
    int lock_flags;

    /* Check we have a valid env var */
    if ( proxy==NULL ) {
	lcmaps_log(LOG_WARNING,
		"%s: environment variable X509_USER_PROXY unset\n", __func__);
	return -1;
    }

    /* Get internal lock flags based on specified lock type */
    switch (lock_type) {
	case LOCK_NOLOCK:
	    lock_flags=LCK_NOLOCK; break;
	case LOCK_FCNTL:
	    lock_flags=LCK_FCNTL; break;
	case LOCK_FLOCK:
	    lock_flags=LCK_FLOCK; break;
	default:
	    lcmaps_log(LOG_ERR, "%s: unknown lock_type %d\n",
		    __func__, lock_type);
	    return -1;
    }

    /* Read in proxy */
    if (read_proxy(proxy, lock_flags, &pem_buf))
	return -1;

    /* Convert PEM buffer to certificate chain */
    rc= pem_string_to_x509_chain(&chain, &privkey, pem_buf);
    free(pem_buf);

    if (rc!=0)   {
	lcmaps_log(LOG_WARNING,
                    "%s: cannot convert pemstring to chain and key.\n",
		    __func__);
	return -1;
    }

    /* Verify that private key belongs to first certificate */
    if (X509_check_private_key(sk_X509_value(chain, 0), privkey) !=1 )    {
	lcmaps_log(LOG_NOTICE,
		"%s: leaf pilot proxy doesn't belong to private key\n",
		__func__);
	EVP_PKEY_free(privkey);
	sk_X509_pop_free(chain, X509_free);
	return -1;
    }

    EVP_PKEY_free(privkey);
    *certstack=chain;

    return 0;
}

/**
 * Gets payload PEM or cert chain from LCMAPS framework
 * \return 0 on success, -1 on error
 */
int psp_get_payload_proxy(STACK_OF(X509) **certstack,
			  int argc, lcmaps_argument_t *argv)	{
    void *value;
    STACK_OF(X509)*chain=NULL;
    char *pem=NULL;

    /* Try to get chain from LCMAPS */
    value=lcmaps_getArgValue("px509_chain", "STACK_OF(X509) *", argc, argv);
    if (value == NULL || (chain = *(STACK_OF(X509) **)value) == NULL ) {
        /* No valid chain found in LCMAPS framework, try to obtain from PEM
         * string */
        lcmaps_log(LOG_DEBUG, "%s: no X.509 chain is set, trying pem string.\n",
                __func__);
        value=lcmaps_getArgValue("pem_string", "char *", argc, argv);
        if (value==NULL || (pem=*(char**)value) == NULL ) {
            /* also not found: fatal error */
            lcmaps_log(LOG_WARNING,
                    "%s: no chain or pemstring is set.\n", __func__);
            return -1;
        }

        /* Convert pem string to chain */
        if (pem_string_to_x509_chain(&chain, NULL, pem)!=0)   {
            lcmaps_log(LOG_WARNING,
                    "%s: cannot convert pemstring to chain.\n", __func__);
            return -1;
        }
	/* Set global variable to keep track of whether we need to clean */
	payload_chain_needs_cleaning=1;
    }

    *certstack=chain;

    return 0;
}

/**
 * Obtains the FQANs from the plugin arguments
 * \return 0 on success, -1 on error
 */
int psp_get_fqans(int *nfqans, char ***fqans, int argc, lcmaps_argument_t *argv)
{
    void *value;

    /* We could try to obtain this information from the voms_data_list argument
     * instead, but we only need the FQANs in any case */
    if ( (value = lcmaps_getArgValue("nfqan", "int", argc, argv) ) )    {
	*nfqans = *(int *)value;
	lcmaps_log(LOG_DEBUG, "%s: found nfqan: %d\n", __func__, *nfqans);
	if (*nfqans>0)   {
	    lcmaps_log(LOG_DEBUG,
		    "%s: the list of FQANs should contain %d elements\n",
		    __func__, *nfqans);
	    if ( (value = lcmaps_getArgValue("fqan_list", "char **",
					     argc, argv)) ) {
		*fqans = *(char ***)value;
		lcmaps_log(LOG_DEBUG, "%s: found list of FQANs\n", __func__);
	    }
	} else {
	    lcmaps_log(LOG_INFO,
		    "%s: No VOMS FQANs present in the proxy chain\n", __func__);
	}
    } else {
	/* Do not fail over to using the FQANs directly from the framework. */
	lcmaps_log(LOG_INFO,
            "%s: No VOMS AC(s) found by the framework in the proxy chain.\n",
            __func__);
    }

    return 0;
}

/**
 * Obtains effective proxy PathLength constraint for leaf proxy in pcpathlen.
 * \return 0 on success, -1 on error
 */
int psp_get_pcpathlen(STACK_OF(X509) *chain, long *pcpathlen) {
    const int purpose=X509_PURPOSE_MIN + X509_PURPOSE_get_by_sname("sslclient");
    int i, depth, eec_index, amount_of_CAs=0;
    long proxy_path_len_countdown=-1;
    X509 *cert=NULL;

    /* Go through chain to look for EEC: count number of CA certs */
    depth = sk_X509_num(chain);

    /* How many CA certs are there in the chain? */
    for (i = 0; i < depth; i++) {
	/* final argument to X509_check_purpose() is whether to check
	 * for CAness */
	if (X509_check_purpose(sk_X509_value(chain, i), purpose, 1))
	    amount_of_CAs++;
    }

    /* Getting the user cert (filtering the CAs and such) */
    eec_index = depth-(amount_of_CAs+1);

    /* Next check also catches depth==0 */
    if (eec_index < 0) {
	/* Counting the stack went wrong. Erroneous stack? */
	lcmaps_log(LOG_NOTICE,
		"%s: cannot parse certificate chain: "
		"depth-(amount_of_CAs+1)=%d < 0\n", __func__, eec_index);
	return -1;
    }

    /* Do we have a proxy cert after the EEC? */
    if (eec_index==0) {
	lcmaps_log(LOG_NOTICE,
		"%s: cannot find proxy cert in chain, EEC seems end\n",
		__func__);
	return -1;
    }

    /* Now go through proxy certificates */
    for (i=eec_index-1; i>=0; i--)    {
	/* Get cert and check it's RFC */
	cert=sk_X509_value(chain, i);
	if (psp_proxy_is_rfc(cert)!=1)    {
	    lcmaps_log(LOG_NOTICE,
		    "%s: proxy at depth %d is not an RFC proxy\n", __func__, i);
	    return -1;
	}

	/* Now check and update the effective remaining proxy path length */
	switch (proxy_path_len_countdown)   {
	    case 0:
		lcmaps_log(LOG_NOTICE,
			"%s: Proxy Path Length Constraint exceeded at "
			"chain-depth %d of %d\n", __func__, i, depth);
		return -1;
	    case -1:
		/* no effective pcpathlen yet: set when we have one now */
		if (cert->ex_pcpathlen != -1)
		    proxy_path_len_countdown=cert->ex_pcpathlen;
		break;
	    default:
		/* already effective pcpathlen */
		if (cert->ex_pcpathlen != -1 &&
		    cert->ex_pcpathlen<proxy_path_len_countdown)
		    /* we have a new one and it is smaller: update */
		    proxy_path_len_countdown=cert->ex_pcpathlen;
		else
		    /* decrease current one */
		    proxy_path_len_countdown--;
		break;
	}

	/* Log on debug where we are */
	lcmaps_log(LOG_DEBUG,
		"%s: effective proxy path length at chain-depth %d is %ld\n",
		__func__, i, proxy_path_len_countdown);
    }

    /* Now set the value */
    *pcpathlen=proxy_path_len_countdown;

    return 0;
}

/**
 * Verifies that payload proxy is signed by pilot proxy
 * \return 0 on success, -1 on error
 */
int psp_verify_proxy_signature(X509 *payload, X509 *pilot)  {
    EVP_PKEY *pilot_key=NULL;
    int result;

    if (pilot==NULL || payload==NULL)	{
	lcmaps_log(LOG_WARNING,
		"%s: pilot or payload proxy is unset.\n", __func__);
	return -1;
    }
    
    /* Get public key from pilot cert */
    if ( (pilot_key = X509_get_pubkey(pilot)) ==NULL ) {
	lcmaps_log(LOG_WARNING, "%s: cannot get public key from pilot cert\n",
		__func__);
	return -1;
    }

    /* Check that payload_cert is signed by the pilot */
    result = X509_verify(payload, pilot_key);

    /* Free memory */
    EVP_PKEY_free(pilot_key);
    if (result!=1)  {
	lcmaps_log(LOG_WARNING,
		"%s: payload cert is not signed by pilot cert\n", __func__);
	return -1;
    }

    return 0;
}

/**
 * Checks whether given proxy certificate is an RFC proxy
 * \return 1 when proxy is RFC compliant, 0 when not
 */
int psp_proxy_is_rfc(X509 *proxy)    {
    int ext_count, i, rfc=0;
    X509_EXTENSION *ex;
    char buffer[OBJ_BUF_SIZE];

    /* Loop of all certificate extensions */
    ext_count=X509_get_ext_count(proxy);
    for (i = 0; i < ext_count; i++) {
        ex = X509_get_ext(proxy, i);
        if (X509_EXTENSION_get_object(ex)) {
            OBJ_obj2txt(buffer, OBJ_BUF_SIZE, X509_EXTENSION_get_object(ex), 1);
            /* Compare found extension if RFC_PROXY OID */
            if (strcmp(buffer, OID_RFC_PROXY) == 0)     {
                rfc=1;
                break;
            }
        }
    }

    return rfc;
}

/**
 * Checks whether given proxy certificate is an RFC Limited proxy
 * \return 1 when proxy is RFC Limited, 0 when not
 */
int psp_proxy_is_limited(X509 *proxy)   {
    char buffer[OBJ_BUF_SIZE];
    int crit=0;
    PROXY_CERT_INFO_EXTENSION *pci = NULL;
    ASN1_OBJECT *policy_lang = NULL;
    ASN1_OBJECT *obj=NULL;
    int nid;
    int rc=0;

    /* Get NID for RFC proxy */
    obj=OBJ_txt2obj(OID_RFC_PROXY,0);
    nid=OBJ_obj2nid(obj);
    ASN1_OBJECT_free(obj);

    /* Get Proxy Certificate Information, its policy and its policyLanguage */
    if ( (pci=X509_get_ext_d2i(proxy, nid, &crit, NULL)) )  {
	if ( pci->proxyPolicy &&
	     (policy_lang=pci->proxyPolicy->policyLanguage) )
	{
	    /* Convert policyLanguage to OID (1 -> always use numerical form) */
	    OBJ_obj2txt(buffer, OBJ_BUF_SIZE, policy_lang, 1);
	    lcmaps_log(LOG_DEBUG,
		    "%s: found policy_lang %s\n", __func__, buffer);
	    /* Check whether it's a LIMITED proxy */
	    if (strcmp(buffer, OID_LIMITED_PROXY)==0)
		rc=1;
	}
	/* Free up memory */
	PROXY_CERT_INFO_EXTENSION_free(pci);
    }

    return rc;
}

/**
 * Checks whether one of the FQANs matches the given pattern
 * \return 1 when found, 0 when not.
 */
int psp_match_fqan(int nfqan, char **fqans, const char *pattern)    {
    int i;

    for (i=0; i<nfqan; i++) {
	if ( fnmatch(pattern, fqans[i], FNM_NOESCAPE)==0 )  {
	    lcmaps_log(LOG_DEBUG, "%s: found FQAN matching %s: %s\n",
		    __func__, pattern, fqans[i]);
	    return 1;
	}
    }
    return 0;
}

/**
 * Gets extra /CN=<...> field of subjectDN of the payload proxy and stores
 * its value into the LCMAPS framework as the user_dn
 * \return 0 on success, -1 on error
 */
int psp_store_proxy_dn(X509 *payload, X509 *pilot)    {
    X509_NAME *subject=NULL;
    char *payload_dn=NULL, *pilot_dn=NULL, *remainder;
    size_t len;
    int rc=-1;

    /* Get payload subjectDN */
    if ( (subject=X509_get_subject_name(payload))==NULL ||
	 (payload_dn=X509_NAME_oneline(subject, NULL, 0))==NULL )
    {
	lcmaps_log(LOG_WARNING, "%s: cannot obtain DN of payload certificate\n",
		__func__);
	return -1;
    }

    /* Get pilot subjectDN */
    if ( (subject=X509_get_subject_name(pilot))==NULL ||
	 (pilot_dn=X509_NAME_oneline(subject, NULL, 0))==NULL )
    {
	lcmaps_log(LOG_WARNING, "%s: cannot obtain DN of pilot certificate\n",
		__func__);
	goto cleanup;
    }

    len=strlen(pilot_dn);
    /* payload DN should be pilot + "/CN=..." */
    if (strlen(payload_dn)<len+4 ||
	strncmp(payload_dn, pilot_dn, len)!=0 ||
	strncmp(payload_dn+len, "/CN=", 4)!=0)
    {
	lcmaps_log(LOG_NOTICE,
		"%s: payload DN \"%s\" does not start with \"%s/CN=\"\n",
		__func__, payload_dn, pilot_dn);
	goto cleanup;
    }
    /* Set pointer to the value after last /CN= */
    remainder=payload_dn+len+4;

    /* Check remainder does NOT start with a slash (/) */
    if (remainder[0]=='/')  {
	lcmaps_log(LOG_NOTICE,
		"%s: invalid value for last proxy /CN: "
		"may not start with a slash (/): \"%s\"\n",
		__func__, remainder);
	goto cleanup;
    }

    /* Add data, afterwards, we can cleanup payload_dn.
     * Note that the SCAS client should look first at the getCredentialData
     * (i.e. the 'run-time' data) and only then 'fallback' at the
     * lcmaps_getArgValue (i.e. the initialize/introspect-time data). */
    rc=addCredentialData(DN, &remainder);
    if (rc==0)
	lcmaps_log(LOG_DEBUG,
		"%s: successfully added user \"%s\" to credential data\n",
		__func__, remainder);
    else
	lcmaps_log(LOG_WARNING,
		"%s: failed to add user \"%s\" to credential data\n",
		__func__, remainder);

cleanup:
    free(payload_dn);
    free(pilot_dn);

    return rc;
}

/**
 * Stores the FQANs in the 'run-time' credential data, such that they can be
 * retrieved using getCredentialData
 * \return 0 on success, -1 on error
 */
int psp_store_fqans(int nfqans, char **fqans) {
    int i;

    /* Store all the FQANs in the framework */
    for (i=0; i<nfqans; i++)    {
	if (addCredentialData(LCMAPS_VO_CRED_STRING, &(fqans[i]))) {
	    lcmaps_log(LOG_WARNING,
		    "%s: failed to add FQAN \"%s\" to credential data\n",
		    __func__, fqans[i]);
	    return -1;
	}
    }
    lcmaps_log(LOG_DEBUG,
	    "%s: successfully added %d FQANs to credential data\n",
	    __func__, nfqans);

    return 0;
}

/**
 * Clean memory in pilot and/or payload chains
 */
void psp_cleanup_chains(STACK_OF(X509) *pilot, STACK_OF(X509) *payload)  {
    if (pilot)
	sk_X509_pop_free(pilot, X509_free);

    if (payload_chain_needs_cleaning && payload)
	sk_X509_pop_free(payload, X509_free);
}


/************************************************************************
 * Private functions
 ************************************************************************/

/*
 * Convert PEM string to stack of X509 certificates and private key. Stack and
 * key need to be cleaned up afterwards. When pkey==NULL, no private key is
 * obtained.
 * \return 0 on success or -1 on error
 */
static int pem_string_to_x509_chain(STACK_OF(X509) **certstack, EVP_PKEY **pkey,
				    char *certstring)
{
    STACK_OF(X509) *mystack=NULL;
    BIO *certbio = NULL;
    STACK_OF(X509_INFO) *sk=NULL;
    EVP_PKEY *myprivkey=NULL;
    X509_INFO *xi;

    /* protect input */
    if (certstack==NULL || certstring==NULL)    {
        lcmaps_log(LOG_ERR,"%s: certstack and/or certstring is NULL\n",
                __func__);
        return -1;
    }

    /* initialize new X509 chain and memory BIO */
    if ( (mystack = sk_X509_new_null()) == NULL ||
         (certbio = BIO_new_mem_buf(certstring, -1)) == NULL)
    {
        lcmaps_log(LOG_ERR,"%s: out of memory\n", __func__);
        return -1;
    }

    /* Convert PEM via memory BIO to stack of X509_INFO */
    sk=PEM_X509_INFO_read_bio(certbio, NULL, NULL, NULL);
    if (!sk)	{
	lcmaps_log(LOG_NOTICE,
		"%s: Cannot convert to stack of X509_INFO\n", __func__);
	BIO_free(certbio);
	goto err;
    }

    /* Do we also want the private key? */
    if (pkey)	{
	/* Reset bio */
	if (BIO_reset(certbio) != 1)	{
	    BIO_free(certbio);
	    goto err;
	}
	/* Now read the private key */
	myprivkey=PEM_read_bio_PrivateKey(certbio, NULL, empty_callback, NULL);
	if (!myprivkey)	{
	    lcmaps_log(LOG_NOTICE, "%s: No private key found\n", __func__);
	    BIO_free(certbio);
	    goto err;
	}
    }

    /* Now cleanup */
    BIO_free(certbio);

    /* Loop over the stack and convert */
    while (sk_X509_INFO_num(sk)) {
        xi=sk_X509_INFO_shift(sk);
	if (xi->x509 != NULL) {
            sk_X509_push(mystack, xi->x509);
            xi->x509=NULL;
        }
        X509_INFO_free(xi);
    }
    sk_X509_INFO_free(sk);

    /* Check there is at least one certificate */
    if (!sk_X509_num(mystack))	{
	lcmaps_log(LOG_NOTICE, "%s: Certificate stack is empty\n", __func__);
        goto err;
    }

    /* Cleanup and return success */
    *certstack=mystack;
    if (pkey)
	*pkey=myprivkey;

    return 0;

err:
    /* Cleanup and error out */
    sk_X509_pop_free(mystack, X509_free);
    EVP_PKEY_free(myprivkey);
    return 1;
}

/**
 * Empty verify callback for reading in the password-less private key
 * \return 0
 */
static int empty_callback(char *buf, int buf_size, int verify, void *cb_tmp) {
     if (buf_size > 0)
	 *buf = '\0';
     return 0;
}

/**
 * Drops privilege to an unprivileged account. 
 * Returns 0 when successful, or the return code of set[ug]id() on error.
 * */
static int priv_drop(uid_t unpriv_uid,gid_t unpriv_gid)  {
    /* drop priv when needed: euid==0, uid!=0 */
    uid_t euid=geteuid();
    gid_t egid=getegid();
    int rc,save_errno;

    /* Anything to be done? Note: unpriv_gid MAY be 0 (root group) */ 
    rc=( unpriv_gid==egid ? 0 : setegid(unpriv_gid) );
    /* If error: don't continue */
    if (rc!=0) return rc;

    /* Anything to be done? unpriv_uid SHOULD NOT be 0 */ 
    rc=( unpriv_uid==0 || unpriv_uid==euid ? 0 : seteuid(unpriv_uid) );
    /* Error: try to restore */
    if (rc!=0)	{
	/* setegid succeeded, seteuid failed */
	save_errno=errno;
	setegid(egid); /* ignore rc of THIS process: damage control */
	errno=save_errno;
    }

    /* return rc of seteuid */
    return rc;
}

/**
 * Tries to raise privilege level back to euid/egid.
 * Return -1 when fails or impossible (neither euid or real uid is root), 0
 * upon success.
 * */
static int raise_priv(uid_t euid, gid_t egid)	{
    uid_t uid=getuid();

    /* reset euid/egid if: it was (effective) root or real user is root */
    if (euid==0)    { /* If target euid==0: do first euid */
	if (seteuid(euid) || setegid(egid))
	    return -1;
	else
	    return 0;
    }
    /* Now situation uid==0 but euid!=0, e.g. root running setuid-nonroot bin */
    if (uid==0)    {
	/* uid==0 but euid is not: do first a seteuid(0) or the setegid will
	 * fail */
	if (seteuid(0) || setegid(egid) || seteuid(euid))
	    return -1;
	else
	    return 0;
    }
    return -1;
}

/**
 * NOTE: This is effectively cgul_filelock, see
 * https://ndpfsvn.nikhef.nl/viewvc/mwsec/trunk/cgul/fileutil/
 * Does given lock action on file given by filedescriptor fd using mechanism
 * defined by lock_type. lock_type can be a multiple types in which case they
 * will be all used. LCK_NOLOCK is a special lock type which just does nothing
 * and will not be combined with others. Valid lock types:
 *  LCK_NOLOCK	- no locking
 *  LCK_FCNTL	- fcntl() locking
 *  LCK_FLOCK	- flock() locking
 * Valid actions are:
 *  LCK_READ	- set shared read lock
 *  LCK_WRITE	- set exclusive write lock
 *  LCK_UNLOCK	- unset lock
 * Locks are exclusive for writing and shared for reading: multiple processes
 * can read simultaneously, but writing is exclusive, both for reading and
 * writing.
 * Returns -1 on error, 0 on success.
 */
static int filelock(int fd, int lock_type, int action) {
    struct flock lck_struct;
    int rc1,rc2;
#ifndef __sun
    int lck;
#endif

    /* Can have multiple lock_types */

    if (lock_type & LCK_NOLOCK)
	return 0;

    /* FLOCK */
    if (lock_type & LCK_FLOCK)	{
#ifdef __sun  /* Should NOT use flock on Solaris */
	return -1;
#else
	switch (action)	{ /* Only one action at the time */
	    case LCK_READ:	lck=LOCK_SH; break;
	    case LCK_WRITE:	lck=LOCK_EX; break;
	    case LCK_UNLOCK:	lck=LOCK_UN; break;
	    default:		return -1;
	}
	rc1=flock(fd, lck);
#endif
    } else
	rc1=0;
    /* FCNTL */
    if (lock_type & LCK_FCNTL)	{
	switch (action)	{ /* Only one action at the time */
	    case LCK_READ:	lck_struct.l_type=F_RDLCK; break;
	    case LCK_WRITE:	lck_struct.l_type=F_WRLCK; break;
	    case LCK_UNLOCK:	lck_struct.l_type=F_UNLCK; break;
	    default:		return -1;
	}
	lck_struct.l_whence=SEEK_SET;
	lck_struct.l_start=0;
	lck_struct.l_len=0;
	rc2=fcntl(fd,F_SETLKW,&lck_struct); /* -1 error */
    } else
	rc2=0;
    return (rc1 || rc2 ? -1 : 0);
}



/**
 * NOTE: this is effectively cgul_read_proxy with some extra logging inserted in
 * here. See https://ndpfsvn.nikhef.nl/viewvc/mwsec/trunk/cgul/fileutil/
 * Reads proxy from *path using given lock_type (see cgul_filelock). It tries to
 * drop privilege to real-uid/real-gid when euid==0 and uid!=0.
 * Space needed will be malloc-ed.
 * Upon successful completion proxy contains the contents of path.
 * Return values:
 * 0: success
 * -1: I/O error
 * -2: privilege-drop error
 * -3: permissions error
 * -4: memory error
 * -5: too many retries needed during reading
 * -6: locking failed
 */
static int read_proxy(const char *path, int lock_type, char **proxy)  {
    const int tries=10; /* max number of retries for reading a changing file */
    int i,fd,rc=0;
    struct stat st1,st2,*sptr1,*sptr2,*sptr3;
    uid_t uid=getuid(),euid=geteuid();
    gid_t gid=getgid(),egid=getegid();
    char *buf,*buf_new; /* *proxy will be updated when everything is ok */
    ssize_t size=0; /* initialize to silence the compiler */

    /* Drop privilege to real uid and real gid, only when we can and are
     * not-root */
    if ( euid==0 && uid!=0 && priv_drop(uid,gid) )  {
	lcmaps_log(LOG_WARNING, "%s: cannot drop privilege\n", __func__);
	return -2;
    }
    /* Open file */
    if ((fd=open(path,O_RDONLY))==-1)	{
	lcmaps_log(LOG_WARNING, "%s: cannot open proxy %s: %s\n",
		__func__, path, strerror(errno));
	raise_priv(euid,egid);
	return -1;
    }
    /* Lock file */
    if (filelock(fd,lock_type,LCK_READ))    {
	close(fd);
	raise_priv(euid,egid);
	return -6;
    }
    /* Stat the file before reading:
     * Need ownership and mode for allowed values, size for malloc */
    if (fstat(fd,&st1))	{
	lcmaps_log(LOG_WARNING, "%s: cannot stat proxy %s: %s\n",
		__func__, path, strerror(errno));
	close(fd);
	raise_priv(euid,egid);
	return -1;
    }
    /* Check we own it (only uid) and it is unreadable/unwriteable for anyone
     * else */ 
    if ( st1.st_uid!=uid || 
	 st1.st_mode & S_IRGRP || st1.st_mode & S_IWGRP ||
	 st1.st_mode & S_IROTH || st1.st_mode & S_IWOTH )   {
	lcmaps_log(LOG_WARNING, "%s: unsafe permissions on proxy %s\n",
		__func__, path);
	close(fd);
	raise_priv(euid,egid);
	return -3;
    }
    /* Get expected space: need 1 extra for trailing '\0' */
    if ( (buf=(char *)malloc((size_t)st1.st_size+sizeof(char)))==NULL)   {
	lcmaps_log(LOG_WARNING, "%s: out of memory\n", __func__);
	close(fd);
	raise_priv(euid,egid);
	return -4;
    }
    /* use pointers to the two so that we can swap them easily */
    sptr1=&st1; sptr2=&st2;
    /* reading retry loop */
    for (i=0; i<tries; i++)   {
	/* Read file: if statted size changes, we will try again */
	size=read(fd,buf,(size_t)sptr1->st_size);
	/* Stat the file */
	if (fstat(fd,sptr2)==-1)    { /* cannot even stat: I/O error */
	    rc=-1; break;
	}
	/* Size, mtime and ctime should have stayed the same, especially ctime
	 * is good as we can't change it with touch ! */
	if ( sptr2->st_size == sptr1->st_size &&	/* size equal */
	     sptr2->st_mtime== sptr1->st_mtime &&	/* mtime equal */
	     sptr2->st_ctime== sptr1->st_ctime)   {	/* ctime equal */
	    /* Just check the return of the read, we might have an I/O error */
	    rc= (size==(ssize_t)sptr1->st_size ? 0 : -1);
	    break;
	}

	/* File has changed during reading: retry */
	if (i<tries-1)	{ /* will be doing a retry */
	    buf_new=(char *)realloc(buf,(size_t)sptr2->st_size+sizeof(char));
	    if ( buf_new==NULL )    {
		rc=-4; break;
	    }
	    buf=buf_new;
	    /* swap struct pointers */
	    sptr3=sptr2; sptr2=sptr1; sptr1=sptr3;
	    /* wait */
	    usleep(500);
	    /* About to read again, make sure we're (again) at the start */
	    if (lseek(fd,(off_t)0,SEEK_SET)!=0)	{ /* I/O error */
		rc=-1; break;
	    }
	} else /* failed too many times */
	    rc=-5;
    }
    
    /* unlock and close the file, ignore exitval: we have read already */
    filelock(fd,lock_type,LCK_UNLOCK);
    close(fd);
    /* reset euid/egid if it was (effective) root. Ignore exit value. */
    raise_priv(euid,egid);
    /* finalize */
    if (rc!=0)	{
	free(buf);
	return rc;
    }
    /* Only now put buf in *proxy */
    buf[size]='\0'; /* Important: read doesn't add the '\0' */
    *proxy=buf;
    return 0;
}
