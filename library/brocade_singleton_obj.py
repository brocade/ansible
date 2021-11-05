#!/usr/bin/env python3

# Copyright 2019 Broadcom. All rights reserved.
# The term 'Broadcom' refers to Broadcom Inc. and/or its subsidiaries.
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import (absolute_import, division, print_function)
__metaclass__ = type


DOCUMENTATION = '''

module: brocade_singleton_obj
short_description: Brocade Fibre Channel generic handler for singleton object
version_added: '2.7'
author: Broadcom BSN Ansible Team <Automation.BSN@broadcom.com>
description:
- Update list of attributes based on module name and object name provided

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
    module_name:
        description:
        - Yang module name. Hyphen or underscore are used interchangebly.
          If the Yang module name is xy-z, either xy-z or xy_z are acceptable.
        required: true
        type: str
    obj_name:
        description:
        - Yang name for the object. Hyphen or underscore are used
          interchangebly. If the Yang list name is xy-z, either
          xy-z or xy_z are acceptable.
        required: true
        type: str
    attributes:
        description:
        - List of attributes for the object. names match rest attributes
          with "-" replaced with "_". Using hyphen in the name
          may result in errenously behavior based on ansible
          parsing.
          - Special node for "brocade-security" module "password" object
            "old_password" and "new_password" are in plain text.
            If "user_name" is user account, only "new_password" is needed.
        required: true
        type: dict
        
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

  - name: change password
    brocade_singleton_obj:
      credential: "{{credential}}"
      vfid: -1
      module_name: "brocade-security"
      obj_name: "password"
      attributes:
        user_name: "user"
        new_password: "xxxx"  
        old_password: "yyyy"

"""


RETURN = """

msg:
    description: Success message
    returned: success
    type: str

"""


"""
Brocade Fibre Channel generic handler for singleton object
"""


from ansible.module_utils.brocade_connection import login, logout, exit_after_login
from ansible.module_utils.brocade_yang import generate_diff, str_to_human, str_to_yang, is_full_human
from ansible.module_utils.brocade_objects import singleton_patch, singleton_get, to_human_singleton, to_fos_singleton, singleton_helper
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
        module_name=dict(required=True, type='str'),
        obj_name=dict(required=True, type='str'),
        attributes=dict(required=True, type='dict'))

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
    module_name = str_to_human(input_params['module_name'])
    obj_name = str_to_human(input_params['obj_name'])
    attributes = input_params['attributes']
    result = {"changed": False}

    singleton_helper(module, fos_ip_addr, fos_user_name, fos_password, https, ssh_hostkeymust, throttle, vfid, module_name, obj_name, attributes, result, timeout)


if __name__ == '__main__':
    main()
