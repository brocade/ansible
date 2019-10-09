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

module: brocade_fibrechannel_configuration_port_configuration
short_description: Brocade Fibre Channel port Configuration
version_added: '2.7'
author: Broadcom BSN Ansible Team <Automation.BSN@broadcom.com>
description:
- Update port configuration

options:

    credential:
        description:
        - login information including
          fos_ip_addr: ip address of the FOS switch
          fos_user_name: login name of FOS switch REST API
          fos_password: password of FOS switch REST API
          https: indicate if HTTPS or HTTP should be used to connect to FOS
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
    port_configuration:
        description:
        - list of port configuraiton attributes. All writable
          attributes supported by BSN REST API with - replaced with _.
          Some examples are
          - portname_mode - portname mode such as dynamic, default, etc.
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

  - name: initial port configuration
    brocade_fibrechannel_configuration_port_configuration:
      credential: "{{credential}}"
      vfid: -1
      port_configuration:
        dynamic_portname_format: "I.T.A.R"
        portname_mode: "dynamic"

"""


RETURN = """

msg:
    description: Success message
    returned: success
    type: str

"""


"""
Brocade Fibre Channel port Configuration
"""


from ansible_collections.daniel_chung_broadcom.fos.plugins.module_utils.brocade_connection import login, logout, exit_after_login
from ansible_collections.daniel_chung_broadcom.fos.plugins.module_utils.brocade_yang import generate_diff
from ansible_collections.daniel_chung_broadcom.fos.plugins.module_utils.brocade_fibrechannel_configuration import port_configuration_patch, port_configuration_get, to_human_port_configuration, to_fos_port_configuration
from ansible.module_utils.basic import AnsibleModule


def main():
    """
    Main function
    """

    argument_spec = dict(
        credential=dict(required=True, type='dict'),
        vfid=dict(required=False, type='int'),
        throttle=dict(required=False, type='float'),
        port_configuration=dict(required=False, type='dict'))

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
    port_configuration = input_params['port_configuration']
    result = {"changed": False}

    if vfid is None:
        vfid = 128

    ret_code, auth, fos_version = login(fos_ip_addr,
                           fos_user_name, fos_password,
                           https, throttle, result)
    if ret_code != 0:
        module.exit_json(**result)

    ret_code, response = port_configuration_get(fos_user_name, fos_password,
                                    fos_ip_addr, fos_version, https,
                                    auth, vfid, result)
    if ret_code != 0:
        exit_after_login(fos_ip_addr, https, auth, result, module)

    resp_port_config = response["Response"]["port-configuration"]

    to_human_port_configuration(resp_port_config)

    diff_attributes = generate_diff(result, resp_port_config, port_configuration)

    result["diff_attributes"] = diff_attributes
    result["resp_port_config"] = resp_port_config
    result["port_configuration"] = port_configuration

    if len(diff_attributes) > 0:
        ret_code = to_fos_port_configuration(diff_attributes, result)
        if ret_code != 0:
            exit_after_login(fos_ip_addr, https, auth, result, module)

        if not module.check_mode:
            ret_code = port_configuration_patch(fos_user_name, fos_password,
                                    fos_ip_addr, fos_version, https,
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
