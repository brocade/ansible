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
import pyfos.pyfos_brocade_zone as pyfos_zone
import pyfos.pyfos_util as pyfos_util
import random
import getpass
import time
import getopt
import sys
import json
import shlex
import atexit
import ast

isHttps = "0"
session = None
ZONE_PREFIX = "az__"

def result_in_empty_cfg(removed_from_defined_cfg, current_cfg):
    if len(removed_from_defined_cfg) == len(current_cfg["member-zone"]["zone-name"]) and sorted(removed_from_defined_cfg) == sorted(current_cfg["member-zone"]["zone-name"]):
        return True
    else:
        return False

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

            if key == "zone_seed":
                ip_addr=value
            elif key == "user":
                user=value
            elif key == "password":
                password=value
            elif key == "checkmode":
                checkmode=ast.literal_eval(value)
            elif key == "target_list":
                target_list=ast.literal_eval(value)
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

    prezone_effective = pyfos_zone.effective_configuration.get(session)
    if pyfos_util.is_failed_resp(prezone_effective):
        print (json.dumps({"changed": False,
            "line": inspect.currentframe().f_lineno,
            "error": prezone_effective}))
        sys.exit()

    prezone_defined = pyfos_zone.defined_configuration.get(session)
    if pyfos_util.is_failed_resp(prezone_defined):
        print (json.dumps({"changed": False,
            "line": inspect.currentframe().f_lineno,
            "error": prezone_defined}))
        sys.exit()

    changed = False
    removed_from_defined_cfg = []

    # walk through the zones and see if they show up in defined config
    # if not, add them.
    for target in target_list:
        for zone in prezone_defined.peek_zone():
            if zone["zone-name"].startswith(ZONE_PREFIX) and target in zone["zone-name"]:
                changed = True
                removed_from_defined_cfg.append(zone["zone-name"])
                if checkmode is False:
                    zones = [
                        {"zone-name" : zone["zone-name"]}
                        ]
                    new_defined = pyfos_zone.defined_configuration()
                    new_defined.set_zone(zones)
                    result = new_defined.delete(session)
                    if pyfos_util.is_failed_resp(result):
                        print (json.dumps({"changed": False,
                            "line": inspect.currentframe().f_lineno,
                            "error": result}))
                        sys.exit()

    if changed:
        if prezone_effective.peek_cfg_name() == None:
            if checkmode is False:
                new_effective = pyfos_zone.effective_configuration()
                new_effective.set_cfg_action(pyfos_zone.CFG_ACTION_SAVE)
                new_effective.set_checksum(prezone_effective.peek_checksum())
                result = new_effective.patch(session)
                if pyfos_util.is_failed_resp(result):
                    print (json.dumps({"changed": False,
                        "line": inspect.currentframe().f_lineno,
                        "error": result}))
                    sys.exit()
        else: 
            if checkmode is False:
                current_cfg = None
                for cfg in prezone_defined.peek_cfg():
                    if cfg["cfg-name"] == prezone_effective.peek_cfg_name():
                        current_cfg = cfg

                if result_in_empty_cfg(removed_from_defined_cfg, current_cfg):
                    cfgs = [
                        {"cfg-name" : prezone_effective.peek_cfg_name()}
                        ]
                    new_defined = pyfos_zone.defined_configuration()
                    new_defined.set_cfg(cfgs)
                    result = new_defined.delete(session)
                    if pyfos_util.is_failed_resp(result):
                        print (json.dumps({"changed": False,
                            "line": inspect.currentframe().f_lineno,
                            "error": result}))
                        sys.exit()

                    new_effective = pyfos_zone.effective_configuration()
                    new_effective.set_cfg_action(pyfos_zone.CFG_ACTION_DISABLE)
                    new_effective.set_checksum(prezone_effective.peek_checksum())
                    result = new_effective.patch(session)
                    if pyfos_util.is_failed_resp(result):
                        print (json.dumps({"changed": False,
                            "line": inspect.currentframe().f_lineno,
                            "error": result}))
                        sys.exit()

                else:
                    cfgs = [
                        {"cfg-name" : prezone_effective.peek_cfg_name(), "member-zone" : {"zone-name" : removed_from_defined_cfg}}
                        ]
                    new_defined = pyfos_zone.defined_configuration()
                    new_defined.set_cfg(cfgs)
                    result = new_defined.delete(session)
                    if pyfos_util.is_failed_resp(result):
                        print (json.dumps({"changed": False,
                            "line": inspect.currentframe().f_lineno,
                            "error": result}))
                        sys.exit()

                    new_effective = pyfos_zone.effective_configuration()
                    new_effective.set_cfg_name(prezone_effective.peek_cfg_name())
                    new_effective.set_checksum(prezone_effective.peek_checksum())
                    result = new_effective.patch(session)
                    if pyfos_util.is_failed_resp(result):
                        print (json.dumps({"changed": False,
                            "line": inspect.currentframe().f_lineno,
                            "error": result}))
                        sys.exit()

    print (json.dumps({
        "changed": changed,
        "zones_removed": removed_from_defined_cfg,
        }))

    pyfos_auth.logout(session)

if __name__ == "__main__": main(sys.argv[1:])
