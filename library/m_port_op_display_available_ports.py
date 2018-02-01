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
            elif key == "mode":
                mode=ast.literal_eval(value)
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
                            session.get(pyfos_auth.CREDENTIAL_KEY)[pyfos_auth.LOGIN_ERROR_KEY]}))
        sys.exit()

    if vfid is not None:
        pyfos_auth.vfid_set(session, vfid)

    changed = False
    result = pyfos_switchfcport.fibrechannel.get(session)
    time.sleep(1)
    if pyfos_util.is_failed_resp(result):
        print (json.dumps({"changed": False,
            "line": inspect.currentframe().f_lineno,
            "error": result}))
        sys.exit()

    available_ports = []
    for port in result:
        neighbor_list = port.peek_neighbor()
        if len(neighbor_list) == 0:
            available_ports.append({'name': port.peek_name(),
                                   'port-type': pyfos_switchfcport.port_type_to_str(port.peek_port_type())}) 

    pyfos_auth.logout(session)

    print (json.dumps({"changed": changed,
                     "available_ports": available_ports}))

if __name__ == "__main__": main(sys.argv[1:])
