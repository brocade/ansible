#!/usr/bin/env python3

# Copyright 2019 Broadcom. All rights reserved.
# The term 'Broadcom' refers to Broadcom Inc. and/or its subsidiaries.
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import (absolute_import, division, print_function)
__metaclass__ = type


DOCUMENTATION = '''

module: brocade_access_gateway_policy
short_description: Brocade Fibre Channel AG policy configuration
version_added: '2.7'
author: Broadcom BSN Ansible Team <Automation.BSN@broadcom.com>
description:
- Update Fibre Channel AG policy configuration

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
    force:
        description:
        - When enabling auto policy, switch is disabled, pg policy is disabled,
          auto policy is enabled, and switch is enabled.
          When enabling pg policy, switch is disabled, auto policy is disabled,
          and switch is enabled.
          If both policies are specified in the playbook, only the first entry
          is processed.
          Pause statement can be used to delay subsequent tasks to be executed
          prior to switch online while executing multiple tasks from the
          same playbook. 
        required: false
        type: bool

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

  - name: AG policy
    brocade_access_gateway_policy
      credential: "{{credential}}"
      vfid: -1
      policy:
        port_group_policy_enabled: True
        auto_policy_enabled: False

"""


RETURN = """

msg:
    description: Success message
    returned: success
    type: str

"""


"""
Brocade Fibre Channel AG policy configuration
"""


from ansible.module_utils.brocade_objects import singleton_helper
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
        policy=dict(required=False, type='dict'),
        force=dict(required=False, type='bool'))

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
    policy = input_params['policy']
    force = input_params['force']
    result = {"changed": False}

    singleton_helper(module, fos_ip_addr, fos_user_name, fos_password, https, True, throttle, vfid, "brocade_access_gateway", "policy", policy, result, timeout, force)


if __name__ == '__main__':
    main()
