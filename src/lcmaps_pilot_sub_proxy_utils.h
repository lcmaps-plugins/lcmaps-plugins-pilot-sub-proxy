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

#ifndef LCMAPS_PILOT_ROBOT_UTILS_H
#define LCMAPS_PILOT_ROBOT_UTILS_H

#include <openssl/x509.h>
#include <lcmaps/lcmaps_arguments.h>


/************************************************************************
 * Typedefs
 ************************************************************************/

typedef enum lock_type_e    {
    LOCK_NOLOCK	= 0,
    LOCK_FLOCK	= 1,
    LOCK_FCNTL	= 2
} lock_type_t;


/************************************************************************
 * Function prototypes
 ************************************************************************/

/**
 * Retrieves the X509_USER_PROXY certificate stack.
 * \return 0 on success, -1 on error.
 */
int psp_get_pilot_proxy(STACK_OF(X509) **certstack, lock_type_t lock_type);

/**
 * Gets payload PEM or cert chain from LCMAPS framework
 * \return 0 on success, -1 on error
 */
int psp_get_payload_proxy(STACK_OF(X509) **certstack,
                      int argc, lcmaps_argument_t *argv);

/**
 * Obtains effective proxy PathLength constraint for leaf proxy in pcpathlen.
 * \return 0 on success, -1 on error
 */
int psp_get_pcpathlen(STACK_OF(X509) *chain, long *pcpathlen);

/**
 * Obtains the FQANs from the plugin arguments
 * \return 0 on success, -1 on error
 */
int psp_get_fqans(int *nfqans, char ***fqans, int argc, lcmaps_argument_t *argv);

/**
 * Verifies that payload proxy is signed by pilot proxy
 * \return 0 on success, -1 on error
 */
int psp_verify_proxy_signature(X509 *payload, X509 *pilot);

/**
 * Checks whether given proxy certificate is an RFC proxy
 * \return 1 when proxy is RFC compliant, 0 when not
 */
int psp_proxy_is_rfc(X509 *proxy);

/**
 * Checks whether given proxy certificate is an RFC Limited proxy
 * \return 1 when proxy is RFC Limited, 0 when not
 */
int psp_proxy_is_limited(X509 *proxy);

/**
 * Checks whether one of the FQANs matches the given pattern
 * \return 1 when found, 0 when not.
 */
int psp_match_fqan(int nfqan, char **fqans, const char *pattern);

/**
 * Gets extra /CN=<...> field of subjectDN of the payload proxy and and stores
 * it into the LCMAPS framework as the user_dn
 * \return 0 on success, -1 on error
 */
int psp_store_proxy_dn(X509 *payload, X509 *pilot);

/**
 * Stores the FQANs in the 'run-time' credential data, such that they can be
 * retrieved using getCredentialData
 * \return 0 on success, -1 on error
 */
int psp_store_fqans(int nfqans, char **fqans);

/**
 * Clean memory in pilot and/or payload chains
 */
void psp_cleanup_chains(STACK_OF(X509) *pilot, STACK_OF(X509) *payload);

#endif /* LCMAPS_PILOT_ROBOT_UTILS_H */
