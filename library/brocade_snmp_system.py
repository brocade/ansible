#!/usr/bin/env python3

# Copyright 2019 Broadcom. All rights reserved.
# The term 'Broadcom' refers to Broadcom Inc. and/or its subsidiaries.
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import (absolute_import, division, print_function)
__metaclass__ = type


DOCUMENTATION = '''

module: brocade_snmp_system
short_description: Brocade Fibre Channel SNMP system configuration
version_added: '2.7'
author: Broadcom BSN Ansible Team <Automation.BSN@broadcom.com>
description:
- Update Fibre Channel SNMP system configuration.

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
    snmp_system:
        description:
        - List of snmp system attributes. All writable attributes supported
          by BSN REST API with - replaced with _.
          Some examples are
          - description - Description string
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

  - name: initial snmp system configuration
    brocade_snmp_system:
      credential: "{{credential}}"
      vfid: -1
      snmp_system:
        audit_interval: 60
        contact: "Field Support."
        description: "DemoSwitch"
        encryption_enabled: False
        informs_enabled: False
        location: "San Jose"
        security_get_level: 0
        security_set_level: 3
        snmpv1_enabled: True

"""


RETURN = """

msg:
    description: Success message
    returned: success
    type: str

"""


"""
Brocade Fibre Channel SNMP system configuration
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
        snmp_system=dict(required=True, type='dict'))

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
    snmp_system = input_params['snmp_system']
    result = {"changed": False}

    singleton_helper(module, fos_ip_addr, fos_user_name, fos_password, https, True, throttle, vfid, "brocade_snmp", "system", snmp_system, result, timeout)


if __name__ == '__main__':
    main()
