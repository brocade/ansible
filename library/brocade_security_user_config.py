#!/usr/bin/env python3

# Copyright 2019 Broadcom. All rights reserved.
# The term 'Broadcom' refers to Broadcom Inc. and/or its subsidiaries.
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import (absolute_import, division, print_function)
__metaclass__ = type


DOCUMENTATION = '''

module: brocade_security_user_config
short_description: Brocade Fibre Channel security user configuration
version_added: '2.7'
author: Broadcom BSN Ansible Team <Automation.BSN@broadcom.com>
description:
- Update Fibre Channel security user configuration

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
    user_configs:
        description:
        - List of user config data structure.
          All writable attributes supported
          by BSN REST API with - replaced with _.
        required: false
        type: list
    delete_user_configs:
        description:
        - List of user config data structure to be deleted
        required: false
        type: list

'''


EXAMPLES = """

  gather_facts: False

  vars:
    credential:
      fos_ip_addr: "{{fos_ip_addr}}"
      fos_user_name: admin
      fos_password: xxx
      https: False

  tasks:

  - name: disable root & user
    brocade_security_user_config:
      credential: "{{credential}}"
      vfid: -1
      user_configs:
        - name: "user"
          account_enabled: False
        - name: "root"
          account_enabled: False

  - name: add new account
    brocade_security_user_config:
      credential: "{{credential}}"
      vfid: -1
      user_configs:
        - name: "myaccount"
          password: "bXlwYXNzd29yZA=="
          virtual_fabric_role_id_list:
            role_id:
              -  "admin=1-128"
          chassis_access_role: "admin"
        - name: "youraccount"
          password: "bXlwYXNzd29yZA=="
          virtual_fabric_role_id_list:
            role_id:
              - "admin=1-128"
          chassis_access_role: "admin"

  - name: delete accounts
    brocade_security_user_config:
      credential: "{{credential}}"
      vfid: -1
      delete_user_configs:
        - name: "myaccount"
        - name: "youraccount"

"""


RETURN = """

msg:
    description: Success message
    returned: success
    type: str

"""


"""
Brocade Fibre Channel user configuration
"""


from ansible.module_utils.brocade_objects import list_helper, list_delete_helper
from ansible.module_utils.basic import AnsibleModule


def main():
    """
    Main function
    """

    argument_spec = dict(
        credential=dict(required=True, type='dict', no_log=True),
        vfid=dict(required=False, type='int'),
        throttle=dict(required=False, type='float'),
        timeout=dict(required=False, type='float'),
        user_configs=dict(required=False, type='list'),
        delete_user_configs=dict(required=False, type='list'))

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
    ssh_hostkeymust = True
    if 'ssh_hostkeymust' in input_params['credential']:
        ssh_hostkeymust = input_params['credential']['ssh_hostkeymust']
    throttle = input_params['throttle']
    timeout = input_params['timeout']
    vfid = input_params['vfid']
    user_configs = input_params['user_configs']
    delete_user_configs = input_params['delete_user_configs']
    result = {"changed": False}

    # if delete user config is not None, then we make sure
    # the user config is not present.
    # user config creation or update does not happen at the same
    # time
    if delete_user_configs != None:
        return list_delete_helper(module, fos_ip_addr, fos_user_name, fos_password, https, ssh_hostkeymust, throttle, vfid, "brocade_security", "user_config", delete_user_configs, True, result, timeout)


    list_helper(module, fos_ip_addr, fos_user_name, fos_password, https, ssh_hostkeymust, throttle, vfid, "brocade_security", "user_config", user_configs, False, result, timeout)


if __name__ == '__main__':
    main()
