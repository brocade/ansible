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

module: brocade_interface_fibrechannel
short_description: Brocade Fibre Channel Port Configuration
version_added: '2.7'
author: Broadcom BSN Ansible Team <Automation.BSN@broadcom.com>
description:
- Update Fibre Channel port configuration

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
    ports:
        description:
        - list of ports to be updated. All writable attributes supported
          by BSN REST API with - replaced with _.
        required: true

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

  - name: Configure ports
    brocade_interface_fibrechannel:
      credential: "{{credential}}"
      vfid: -1
      ports:
        - name: "0/0"
          enabled_state: False 
          npiv_pp_limit: 126
        - name: "0/1"
          persistent_disable: True

"""


RETURN = """

msg:
    description: Success message
    returned: success
    type: str

"""


"""
Brocade Fibre Channel Port Configuration
"""


from ansible.module_utils.brocade_connection import login, logout, exit_after_login
from ansible.module_utils.brocade_interface import fc_port_patch, fc_port_get, to_human_fc, to_fos_fc
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.brocade_yang import generate_diff, is_full_human


def main():
    """
    Main function
    """

    argument_spec = dict(
        credential=dict(required=True, type='dict', no_log=True),
        vfid=dict(required=False, type='int'),
        throttle=dict(required=False, type='float'),
        ports=dict(required=True, type='list'))

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
    ports = input_params['ports']
    result = {"changed": False}

    if not is_full_human(ports, result):
        module.exit_json(**result)

    if vfid is None:
        vfid = 128

    ret_code, auth, fos_version = login(fos_ip_addr,
                           fos_user_name, fos_password,
                           https, throttle, result)
    if ret_code != 0:
        module.exit_json(**result)

    ret_code, response = fc_port_get(fos_ip_addr, https, auth, vfid, result)
    if ret_code != 0:
        exit_after_login(fos_ip_addr, https, auth, result, module)

    resp_ports = response["Response"]["fibrechannel"]
    if isinstance(resp_ports, list):
        current_ports = resp_ports
    else:
        current_ports = [resp_ports]

    diff_ports = []
    for port in ports:
        for current_port in current_ports:
            if port["name"] == current_port["name"]:
                to_human_fc(current_port)
                diff_attributes = generate_diff(result, current_port, port)
                if len(diff_attributes) > 0:
                    result["current_port"] = current_port
                    diff_attributes["name"] = port["name"]
                    ret_code = to_fos_fc(diff_attributes, result)
                    if ret_code != 0:
                        exit_after_login(fos_ip_addr, https, auth, result, module)
                    diff_ports.append(diff_attributes)

    result["diff_ports"] = diff_ports

    if len(diff_ports) > 0:
        if not module.check_mode:
            ret_code = fc_port_patch(fos_ip_addr, https,
                                     auth, vfid, result, diff_ports)
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
