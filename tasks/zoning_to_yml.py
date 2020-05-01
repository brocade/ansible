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

"""

:mod:`zoning_to_yml` - PyFOS util for specific Zoning use case.
***********************************************************************************
The :mod:`zoning_to_yml` provides for specific Zoning use case.

This module is a standalone script to display Zone DB in yml.

* inputs:
    * -L=<login>: Login ID. If not provided, interactive
        prompt will request one.
    * -P=<password>: Password. If not provided, interactive
        prompt will request one.
    * -i=<IP address>: IP address
    * -f=<VFID>: VFID or -1 if VF is disabled. If unspecified,
        VFID of 128 is assumed.

* outputs:
    * Python dictionary content with RESTCONF response data

"""

import sys
from pyfos import pyfos_auth
import pyfos.pyfos_brocade_zone as pyfos_zone
from pyfos import pyfos_util
from pyfos.utils import brcd_util


def usage():
    print("")


def main(argv):
    valid_options = []
    inputs = brcd_util.generic_input(argv, usage, valid_options)

    session = pyfos_auth.login(inputs["login"], inputs["password"],
                               inputs["ipaddr"], inputs["secured"],
                               verbose=inputs["verbose"])
    if pyfos_auth.is_failed_login(session):
        print("login failed because",
              session.get(pyfos_auth.CREDENTIAL_KEY)
              [pyfos_auth.LOGIN_ERROR_KEY])
        brcd_util.full_usage(usage, valid_options)
        sys.exit()

    brcd_util.exit_register(session)

    vfid = None
    if 'vfid' in inputs:
        vfid = inputs['vfid']

    if vfid is not None:
        pyfos_auth.vfid_set(session, vfid)

    defined_zone = pyfos_zone.defined_configuration.get(session)

    print("aliases:")
    for alias in defined_zone.peek_alias():
        print("  - name:", alias["alias-name"])
        print("    members:")
        for member in alias["member-entry"]["alias-entry-name"]:
            print("      - ", member)

    print()

    print("zones:")
    for zone in defined_zone.peek_zone():
        print("  - name:", zone["zone-name"])
        if len(zone["member-entry"]["entry-name"]) > 0:
            print("    members:")
            for member in zone["member-entry"]["entry-name"]:
                print("      - ", member)
        if len(zone["member-entry"]["principal-entry-name"]) > 0:
            print("    principal_members:")
            for member in zone["member-entry"]["principal-entry-name"]:
                print("      - ", member)

    print()

    print("cfgs:")
    for cfg in defined_zone.peek_cfg():
        print("  - name:", cfg["cfg-name"])
        print("    members:")
        for member in cfg["member-zone"]["zone-name"]:
            print("      - ", member)

    # effective_zone = pyfos_zone.effective_configuration.get(session)
    # pyfos_util.response_print(effective_zone)

    # options = effective_zone.options(session)
    # print(options)

    pyfos_auth.logout(session)


if __name__ == "__main__":
    main(sys.argv[1:])
