#!/usr/bin/env python3

# Copyright 2018 Brocade Communications Systems LLC.  All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may also obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import pyfos.pyfos_auth as pyfos_auth
import pyfos.pyfos_zone as pyfos_zone
import pyfos.pyfos_util as pyfos_util
import pyfos.utils.zoning.zone_allow_pair as zone_allow_pair
import random
import getpass
import time
import getopt
import sys
import json
import shlex
import atexit
import ast
import inspect

isHttps = "0"
session = None
ZONE_PREFIX = "az__"

def exit_handler():
    global session
    if session != None:
        pyfos_auth.logout(session)


def main(argv):
    global session

    atexit.register(exit_handler)

    args_file = sys.argv[1]
    args_data = open(args_file).read()

    vfid = None

    arguments = shlex.split(args_data)
    for arg in arguments:
        if "=" in arg:
            (key, value) = arg.split("=")

            if key == "acl_name":
                cfgname=value
            elif key == "zone_seed":
                ip_addr=value
            elif key == "user":
                user=value
            elif key == "password":
                password=value
            elif key == "apply_peer_zone":
                user=value
            elif key == "checkmode":
                checkmode=ast.literal_eval(value)
            elif key == "zone_acl":
                zone_acl=ast.literal_eval(value)
            elif key == "zone_prefix":
                ZONE_PREFIX=value
            elif key == "vfid":
                vfid=ast.literal_eval(value)

#        print json.dumps({
#                "ip_addr" : ip_addr,
#                "checkmode" : checkmode,
#                "zone_acl" : zone_acl
#                "zone_prefix" : zone_prefix
#        })


    session = pyfos_auth.login(user, password, ip_addr, isHttps)
    if pyfos_auth.is_failed_login(session):
        print (json.dumps({"changed": False,
            "login failed reason":
            session.get(pyfos_auth.CREDENTIAL_KEY)[pyfos_auth.LOGIN_ERROR_KEY]    }))
        sys.exit()

    if vfid is not None:
        pyfos_auth.vfid_set(session, vfid)

    changed = False
    add_to_cfg = []
    added_to_defined_cfg_zonenames = []
    exist_in_defined_cfg_zonenames = []

    # walk through the zones and see if they show up in defined config
    # if not, add them.
    for zone in zone_acl:
        hostname = zone[0]
        targetname = zone[1]
        hostport = zone[2]
        targetport = zone[3]
       
        ret_code, result = zone_allow_pair.zone_allow_pair(
            session, ZONE_PREFIX, hostname, hostport,
            targetname, targetport, cfgname, checkmode)
       
        # if any returns changed, we return changed
        if ret_code > 0:
            changed = True

        zonename = zone_allow_pair.zonename_get(ZONE_PREFIX, hostname, targetname)

        if ret_code == zone_allow_pair.RET_ZONE_CREATED_ADDED_TO_NEW_CFG:
            add_to_cfg.append(zonename)
            added_to_defined_cfg_zonenames.append(zonename)
        elif ret_code == zone_allow_pair.RET_ZONE_EXIST_ADDED_TO_NEW_CFG:
            add_to_cfg.append(zonename)
            exist_in_defined_cfg_zonenames.append(zonename)
        elif ret_code == zone_allow_pair.RET_ZONE_CREATED_ADDED_TO_CFG:
            add_to_cfg.append(zonename)
            added_to_defined_cfg_zonenames.append(zonename)
        elif ret_code == zone_allow_pair.RET_ZONE_EXIST_ADDED_TO_CFG:
            add_to_cfg.append(zonename)
            exist_in_defined_cfg_zonenames.append(zonename)
        elif ret_code == zone_allow_pair.RET_ZONE_CREATED_IN_CFG:
            added_to_defined_cfg_zonenames.append(zonename)
        elif ret_code == zone_allow_pair.RET_ZONE_EXIST_IN_CFG:
            exist_in_defined_cfg_zonenames.append(zonename)

    print (json.dumps({
        "changed": changed,
        "acl_name": cfgname,
        "added_to_acl": add_to_cfg,
        "added_zones": added_to_defined_cfg_zonenames,
        "existing_zones": exist_in_defined_cfg_zonenames,
        }))

    pyfos_auth.logout(session)

if __name__ == "__main__": main(sys.argv[1:])
