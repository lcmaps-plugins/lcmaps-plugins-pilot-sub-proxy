/**                                                                                               
 * Copyright (c) Members of the EGEE Collaboration. 2004-2010.                                    
 * See http://www.eu-egee.org/partners/ for details on the copyright                              
 * holders.                                                                                       
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
 *  2009-
 *     Oscar Koeroo <okoeroo@nikhef.nl>
 *     Mischa Sall\'e <msalle@nikhef.nl>
 *     David Groep <davidg@nikhef.nl>
 *     NIKHEF Amsterdam, the Netherlands
 *     <grid-mw-security@nikhef.nl> 
 *
 *  2007-2009
 *     Oscar Koeroo <okoeroo@nikhef.nl>
 *     David Groep <davidg@nikhef.nl>
 *     NIKHEF Amsterdam, the Netherlands
 *
*
 *  2003-2007
 *     Martijn Steenbakkers <martijn@nikhef.nl>
 *     Gerben Venekamp <venekamp@nikhef.nl>
 *     Oscar Koeroo <okoeroo@nikhef.nl>
 *     David Groep <davidg@nikhef.nl>
 *     NIKHEF Amsterdam, the Netherlands
 *
 */


/*!
    \file   lcmaps_plugin_prototypes.h
    \brief  plugin function prototypes
*/

#ifndef LCMAPS_PLUGIN_PROTOTYPES_H
#define LCMAPS_PLUGIN_PROTOTYPES_H

#include "lcmaps_plugin_typedefs.h"

/******************************************************************************
Function:   plugin_initialize
Description:
    Initialize plugin
Parameters:
    int argc, char **argv
    argv[0]: the name of the plugin
Returns:
    LCMAPS_MOD_SUCCESS : succes
    LCMAPS_MOD_FAIL    : failure
    LCMAPS_MOD_NOFILE  : db file not found (will halt LCMAPS initialization)
******************************************************************************/
plugin_initialize_t plugin_initialize;

/******************************************************************************
Function:   plugin_introspect
Description:
    return list of required arguments as argc,argv
Parameters:
    int *argc, lcmaps_argument_t **argv

Returns:
    LCMAPS_MOD_SUCCESS : succes
    LCMAPS_MOD_FAIL    : failure
******************************************************************************/
plugin_introspect_t plugin_introspect;

/******************************************************************************
Function:   plugin_run
Description:
    Gather credentials for LCMAPS
Parameters:
    int argc: number of arguments
    lcmaps_argument_t *argv: list of arguments
Returns:
    LCMAPS_MOD_SUCCESS: authorization succeeded
    LCMAPS_MOD_FAIL   : authorization failed
******************************************************************************/
plugin_run_t plugin_run;

/******************************************************************************
Function:   plugin_verify
Description:
    Verify if user is entitled to use local credentials based on his grid
    credentials. This means that the site should already have been set up
    by, e.g., LCMAPS in a previous run. This method will not try to setup
    account leases, modify (distributed) passwd/group files, etc. etc.
    The outcome should be identical to that of plugin_run().
    In this particular case "plugin_verify()" is identical to "plugin_run()"

Parameters:
    int argc: number of arguments
    lcmaps_argument_t *argv: list of arguments
Returns:
    LCMAPS_MOD_SUCCESS: authorization succeeded
    LCMAPS_MOD_FAIL   : authorization failed
******************************************************************************/
plugin_verify_t plugin_verify;

/******************************************************************************
Function:   plugin_terminate
Description:
    Terminate plugin
Parameters:

Returns:
    LCMAPS_MOD_SUCCESS : succes
    LCMAPS_MOD_FAIL    : failure
******************************************************************************/
plugin_terminate_t plugin_terminate;

#endif /* LCMAPS_PLUGIN_PROTOTYPES_H */
