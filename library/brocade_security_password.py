#!/usr/bin/python

# Copyright 2019-2025 Broadcom. All rights reserved.
# The term 'Broadcom' refers to Broadcom Inc. and/or its subsidiaries.
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import (absolute_import, division, print_function)
__metaclass__ = type


DOCUMENTATION = '''

module: brocade_security_password
short_description: Brocade Fibre Channel security password change
version_added: '2.7'
author: Broadcom BSN Ansible Team <Automation.BSN@broadcom.com>
description:
- Update password for a given user

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
    password:
        description:
        - Password change attributes.
          - user_name - name of the account.
          - old_password - old password in clear text.
          - new_password - new password in clear text.
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
    brocade_security_password:
      credential: "{{credential}}"
      vfid: -1
      password:
        user_name: user
        old_password: oldpassword
        new_password: newpassword

"""


RETURN = """

msg:
    description: Success message
    returned: success
    type: str

"""


"""
Brocade Fibre Channel security password change
"""


from ansible.module_utils.brocade_objects import singleton_helper
from ansible.module_utils.basic import AnsibleModule


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
        timeout=dict(required=False, type='int'),
        password=dict(required=True, type='dict'))

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
    password = input_params['password']
    result = {"changed": False}

    singleton_helper(module, fos_ip_addr, fos_user_name, fos_password, https, ssh_hostkeymust, throttle, vfid, "brocade_security", "password", password, result, timeout)


if __name__ == '__main__':
    main()
