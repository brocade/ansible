#!/usr/bin/python

# Copyright 2019-2025 Broadcom. All rights reserved.
# The term 'Broadcom' refers to Broadcom Inc. and/or its subsidiaries.
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import (absolute_import, division, print_function)
__metaclass__ = type


DOCUMENTATION = '''

module: brocade_zoning_cfg_disable
short_description: Brocade Fibre Channel zoning disable configuration
version_added: '2.7'
author: Broadcom BSN Ansible Team <Automation.BSN@broadcom.com>
description:
- Disable the cfgs that was effective.

options:
    credential:
        description:
        - Login information
        suboptions:
            fos_ip_addr:
                description:
                - IP address of the FOS switch
                required: true
                type: str
            fos_user_name:
                description:
                - Login name of FOS switch
                required: true
                type: str
            fos_password:
                description:
                - Password of FOS switch
                required: true
                type: str
            https:
                description:
                - Encryption to use. True for HTTPS, self for self-signed HTTPS, 
                  or False for HTTP
                choices:
                    - True
                    - False
                    - self
                required: true
                type: str

        type: dict
        required: true
    vfid:
        description:
        - VFID of the switch. Use -1 for FOS without VF enabled or AG. 
        type: int
        required: false
    throttle:
        description:
        - Throttling delay in seconds. Enables second retry on first
          failure.
        type: int
    timeout:
        description:
        - REST timeout in seconds for operations that take longer than FOS
          default value.
        type: int
    disable_cfg:
        description:
        - Cfg to be disabled.
        required: false
        type: bool
 
'''


EXAMPLES = """

  gather_facts: False

  vars:
    credential:
      fos_ip_addr: "{{fos_ip_addr}}"
      fos_user_name: admin
      fos_password: password
      https: False

  tasks:

  - name: Disable cfgs
    brocade_zoning_cfg_disable:
      credential: "{{credential}}"
      vfid: -1

"""


RETURN = """

msg:
    description: Success message
    returned: success
    type: str

"""

"""
Brocade Fibre Channel zoning cfg disable
"""


from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.brocade_connection import login, logout, exit_after_login
from ansible.module_utils.brocade_zoning import zoning_common, cfg_post, cfg_delete, cfg_get, cfg_process_diff, cfg_process_diff_to_delete


def main():
    """
    Main function
    """

    argument_spec = dict(
        credential=dict(required=True, type='dict', options=dict(
            fos_ip_addr=dict(required=True, type='str'),
            fos_user_name=dict(required=True, type='str'),
            fos_password=dict(required=True, type='str', no_log=True),
            https=dict(required=True, type='str'),
            ssh_hostkeymust=dict(required=False, type='bool'))),
        vfid=dict(required=False, type='int'),
        throttle=dict(required=False, type='int'),
        timeout=dict(required=False, type='int'))

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
    timeout = input_params['timeout']
    vfid = input_params['vfid']
    result = {"changed": False}
    disable_cfg=True

    if vfid is None:
        vfid = 128

    ret_code, auth, fos_version = login(fos_ip_addr,
                           fos_user_name, fos_password,
                           https, throttle, result, timeout)
    if ret_code != 0:
        module.exit_json(**result)

    zoning_common(fos_ip_addr, https, fos_version, auth, vfid, result, module, None,
                  None, None, None, "cfg",
                  cfg_process_diff, cfg_process_diff_to_delete,
                  cfg_get, cfg_post, cfg_delete, None, disable_cfg, timeout)

    ret_code = logout(fos_ip_addr, https, auth, result, timeout)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
