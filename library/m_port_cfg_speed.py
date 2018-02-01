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
import pyfos.pyfos_switchfcport as pyfos_switchfcport
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
import inspect

isHttps = "0"
session = None

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

            if key == "switch_ip":
                ip_addr=value
            elif key == "user":
                user=value
            elif key == "password":
                password=value
            elif key == "checkmode":
                checkmode=ast.literal_eval(value)
            elif key == "name":
                name=value
            elif key == "speed":
                speed=value
            elif key == "vfid":
                vfid=ast.literal_eval(value)

#        print json.dumps({
#                "ip_addr" : ip_addr,
#                "user" : user,
#                "password" : password,
#                "checkmode" : checkmode
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

    current_port_info = pyfos_switchfcport.fibrechannel.get(session, name)
    time.sleep(1)
    if pyfos_util.is_failed_resp(current_port_info):
        print (json.dumps({"changed": False,
            "line": inspect.currentframe().f_lineno,
            "error": current_port_info}))
        sys.exit()

    if speed == "0":
        new_speed = pyfos_switchfcport.SPEED_TYPE.AUTO
    elif speed == "1":
        new_speed = pyfos_switchfcport.SPEED_TYPE.G1FC
    elif speed == "2":
        new_speed = pyfos_switchfcport.SPEED_TYPE.G2FC
    elif speed == "4":
        new_speed = pyfos_switchfcport.SPEED_TYPE.G4FC
    elif speed == "8":
        new_speed = pyfos_switchfcport.SPEED_TYPE.G8FC
    elif speed == "10":
        new_speed = pyfos_switchfcport.SPEED_TYPE.G10FC
    elif speed == "16":
        new_speed = pyfos_switchfcport.SPEED_TYPE.G16FC
    elif speed == "32":
        new_speed = pyfos_switchfcport.SPEED_TYPE.G32FC
    elif speed == "128":
        new_speed = pyfos_switchfcport.SPEED_TYPE.G128FC

    old_speed = current_port_info.peek_speed()
    if (new_speed == pyfos_switchfcport.SPEED_TYPE.AUTO and current_port_info.peek_auto_negotiate() != 1) or (new_speed != pyfos_switchfcport.SPEED_TYPE.AUTO and current_port_info.peek_speed() != new_speed and current_port_info.peek_auto_negotiate() != 1) or (new_speed != pyfos_switchfcport.SPEED_TYPE.AUTO and current_port_info.peek_auto_negotiate() == 1):
        changed = True
        if checkmode is False:
            port = pyfos_switchfcport.fibrechannel()
            port.set_name(name)
            port.set_speed(new_speed)
            result = port.patch(session)
            time.sleep(1)
            if pyfos_util.is_failed_resp(result):
                print ((json.dumps({"changed": False,
                    "line": inspect.currentframe().f_lineno,
                    "error": result})))
                sys.exit()

    pyfos_auth.logout(session)

    if changed:
        if new_speed == pyfos_switchfcport.SPEED_TYPE.AUTO:
            print (json.dumps({
                "changed": changed,
                "speed": "auto negotiate"
                }))
        else:
            if current_port_info.peek_auto_negotiate() == 1:
                print (json.dumps({
                    "changed": changed,
                    "old speed": "auto negotiate",
                    "new speed": str(new_speed),
                    }))
            else:
                print (json.dumps({
                    "changed": changed,
                    "old speed": old_speed,
                    "new speed": str(new_speed),
                    }))
    else:
        print (json.dumps({
            "changed": changed,
        }))

if __name__ == "__main__": main(sys.argv[1:])
