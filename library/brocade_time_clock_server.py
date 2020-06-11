#!/usr/bin/python

# Copyright 2019 Broadcom. All rights reserved.
# The term 'Broadcom' refers to Broadcom Inc. and/or its subsidiaries.
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import (absolute_import, division, print_function)
__metaclass__ = type


ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'certified'}


DOCUMENTATION = '''

module: brocade_time_clock_server
short_description: Brocade time clock server Configuration
version_added: '2.7'
author: Broadcom BSN Ansible Team <Automation.BSN@broadcom.com>
description:
- Update time clock server configuration. Legacy implementation.
  but still works. Recommends using brocade_singleton_obj(_facts) instead.

options:

    credential:
        description:
        - login information including
          fos_ip_addr: ip address of the FOS switch
          fos_user_name: login name of FOS switch REST API
          fos_password: password of FOS switch REST API
          https: True for HTTPS, self for self-signed HTTPS, or False for HTTP
        type: dict
        required: true
    vfid:
        description:
        - vfid of the switch to target. The value can be -1 for
          FOS without VF enabled. For VF enabled FOS, a valid vfid
          should be given
        required: false
    throttle:
        description:
        - rest throttling delay in seconds.
        required: false
    clock_server:
        description:
        - clock server data structure containing ntp servers
          WARNING: if ntp servers are not reachable, the operation
          may result in time out and playbook returning failure
          All writable attributes supported
          by BSN REST API with - replaced with _.
        required: false

'''


EXAMPLES = """

  gather_facts: False

  vars:
    credential:
      fos_ip_addr: "{{fos_ip_addr}}"
      fos_user_name: admin
      fos_password: xxxx
      https: False

  tasks:

  - name: initial clock server configuration
    brocade_time_clock_server:
      credential: "{{credential}}"
      vfid: -1
      clock_server:
        ntp_server_address:
          server_address:
            - "10.38.2.80"
            - "10.38.2.81"

"""


RETURN = """

msg:
    description: Success message
    returned: success
    type: str

"""


"""
Brocade Fibre Channel time clock server Configuration
"""


from ansible.module_utils.brocade_connection import login, logout, exit_after_login
from ansible.module_utils.brocade_yang import generate_diff, is_full_human
from ansible.module_utils.brocade_time import clock_server_patch, clock_server_get, to_human_clock_server, to_fos_clock_server
from ansible.module_utils.basic import AnsibleModule


def main():
    """
    Main function
    """

    argument_spec = dict(
        credential=dict(required=True, type='dict', no_log=True),
        vfid=dict(required=False, type='int'),
        throttle=dict(required=False, type='float'),
        clock_server=dict(required=False, type='dict'))

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True
    )

    input_params = module.params

    # Set up state variables
    fos_ip_addr = input_params['credential']['fos_ip_addr']
    fos_user_name = input_params['credential']['fos_user_name']
    fos_password = input_params['credential']['fos_password']
    https = input_params['credential']['https']
    throttle = input_params['throttle']
    vfid = input_params['vfid']
    clock_server = input_params['clock_server']
    result = {"changed": False}

    if not is_full_human(clock_server, result):
        module.exit_json(**result)

    if vfid is None:
        vfid = 128

    ret_code, auth, fos_version = login(fos_ip_addr,
                           fos_user_name, fos_password,
                           https, throttle, result)
    if ret_code != 0:
        module.exit_json(**result)

    ret_code, response = clock_server_get(
        fos_ip_addr, https, auth, vfid, result)
    if ret_code != 0:
        exit_after_login(fos_ip_addr, https, auth, result, module)

    resp_clock = response["Response"]["clock-server"]

    to_human_clock_server(resp_clock)

    if "ntp_server_address" in resp_clock and "server_address" in resp_clock["ntp_server_address"]:
        if not isinstance(resp_clock["ntp_server_address"]["server_address"], list):
            new_list = []
            new_list.append(resp_clock["ntp_server_address"]["server_address"])
            resp_clock["ntp_server_address"]["server_address"] = new_list

    diff_attributes = generate_diff(result, resp_clock, clock_server)

    result["diff_attributes"] = diff_attributes
    result["clock_server"] = clock_server
    result["resp_clock"] = resp_clock

    if len(diff_attributes) > 0:
        ret_code = to_fos_clock_server(diff_attributes, result)
        if ret_code != 0:
            exit_after_login(fos_ip_addr, https, auth, result, module)

        if not module.check_mode:
            ret_code = clock_server_patch(
                fos_ip_addr, https,
                auth, vfid, result, diff_attributes)
            if ret_code != 0:
                exit_after_login(fos_ip_addr, https, auth, result, module)

        result["changed"] = True
    else:
        logout(fos_ip_addr, https, auth, result)
        module.exit_json(**result)

    logout(fos_ip_addr, https, auth, result)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
