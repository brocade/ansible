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
from pyfos.utils.zoning.zone_allow_pair import zone_allow_pair
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
ZONE_PREFIX = "az_tupl_"
CFG_NAME = "az__cfg"

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

            if key == "host_name":
                hostname=value
            if key == "target_name":
                targetname=value
            elif key == "host_port":
                hostport=value
            elif key == "target_port":
                targetport=value
            elif key == "zone_seed":
                ip_addr=value
            elif key == "user":
                user=value
            elif key == "password":
                password=value
            elif key == "checkmode":
                checkmode=ast.literal_eval(value)
            elif key == "zone_prefix":
                ZONE_PREFIX=value
            elif key == "zone_postfix":
                zone_postfix=value
            elif key == "vfid":
                vfid=ast.literal_eval(value)

#        print json.dumps({
#                "hostname" : hostname,
#                "hostport" : hostport,
#                "targetport" : targetport,
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

    ret_code, result = zone_allow_pair(
            session, ZONE_PREFIX, hostname, hostport,
            targetname, targetport, CFG_NAME, checkmode)

    if ret_code > 0:
        result["changed"] = True
    else:
        result["changed"] = False

    print (json.dumps(result))

    pyfos_auth.logout(session)

if __name__ == "__main__": main(sys.argv[1:])
