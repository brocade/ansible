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

module: brocade_security_user_config
short_description: Brocade security user config Configuration
version_added: '2.7'
author: Broadcom BSN Ansible Team <Automation.BSN@broadcom.com>
description:
- Update security user config configuration.


options:

    credential:
        description:
        - login information including
          fos_ip_addr - ip address of the FOS switch
          fos_user_name - login name of FOS switch REST API
          fos_password - password of FOS switch REST API
          https - True for HTTPS, self for self-signed HTTPS, or False for HTTP
          ssh_hostkeymust - hostkeymust arguement for ssh attributes only. Default True.
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
        - rest throttling delay in seconds to retry once more if
          server is busy.
        required: false
    timeout:
        description:
        - rest timeout in seconds for operations taking longer than
          default timeout.
        required: false
    user_configs:
        description:
        - list of user config data structure
          All writable attributes supported
          by BSN REST API with - replaced with _.
        required: false
    delete_user_configs:
        description:
        - list of user config data structure to be deleted
        required: false

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
Brocade Fibre Channel user config Configuration
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
