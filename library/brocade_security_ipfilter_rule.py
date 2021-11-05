#!/usr/bin/env python3

# Copyright 2019 Broadcom. All rights reserved.
# The term 'Broadcom' refers to Broadcom Inc. and/or its subsidiaries.
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import (absolute_import, division, print_function)
__metaclass__ = type


DOCUMENTATION = '''

module: brocade_security_ipfilter_rule
short_description: Brocade Fibre Channel security ipfilter rule Configuration
version_added: '2.7'
author: Broadcom BSN Ansible Team <Automation.BSN@broadcom.com>
description:
- Update Fibre Channel secuirty ipfilter rule configuration

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
    ipfilter_rules:
        description:
        - List of ipfilter rules data structure.
          All writable attributes supported
          by BSN REST API with - replaced with _.
        required: true
        type: list

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

  - name: ipfilter policy is created or present
    brocade_security_ipfilter_policy:
      credential: "{{credential}}"
      vfid: -1
      ipfilter_policies:
        - name: "ipv4_telnet_http"
          ip_version: "IPv4"

  - name: ipfilter rules are created or present
    brocade_security_ipfilter_rule:
      credential: "{{credential}}"
      vfid: -1
      ipfilter_rules:
        - policy_name: "ipv4_telnet_http"
          index: 1
          destination_end_port: 22
          destination_ip: "any"
          destination_start_port: 22
          permission: "permit"
          protocol: "tcp"
          source_ip: "any"
          traffic_type: "INPUT"
        - policy_name: "ipv4_telnet_http"
          index: 2
          destination_end_port: 23
          destination_ip: "any"
          destination_start_port: 23
          permission: "deny"
          protocol: "tcp"
          source_ip: "any"
          traffic_type: "INPUT"
        - policy_name: "ipv4_telnet_http"
          index: 3
          destination_end_port: 80
          destination_ip: "any"
          destination_start_port: 80
          permission: "permit"
          protocol: "tcp"
          source_ip: "any"
          traffic_type: "INPUT"
        - policy_name: "ipv4_telnet_http"
          index: 4
          destination_end_port: 443
          destination_ip: "any"
          destination_start_port: 443
          permission: "permit"
          protocol: "tcp"
          source_ip: "any"
          traffic_type: "INPUT"
        - policy_name: "ipv4_telnet_http"
          index: 5
          destination_end_port: 161
          destination_ip: "any"
          destination_start_port: 161
          permission: "permit"
          protocol: "udp"
          source_ip: "any"
          traffic_type: "INPUT"
        - policy_name: "ipv4_telnet_http"
          index: 6
          destination_end_port: 123
          destination_ip: "any"
          destination_start_port: 123
          permission: "permit"
          protocol: "udp"
          source_ip: "any"
          traffic_type: "INPUT"
        - policy_name: "ipv4_telnet_http"
          index: 7
          destination_end_port: 1023
          destination_ip: "any"
          destination_start_port: 600
          permission: "permit"
          protocol: "tcp"
          source_ip: "any"
          traffic_type: "INPUT"
        - policy_name: "ipv4_telnet_http"
          index: 8
          destination_end_port: 1023
          destination_ip: "any"
          destination_start_port: 600
          permission: "permit"
          protocol: "udp"
          source_ip: "any"
          traffic_type: "INPUT"
        - policy_name: "ipv4_telnet_http"
          index: 9
          destination_end_port: 389
          destination_ip: "any"
          destination_start_port: 389
          permission: "permit"
          protocol: "tcp"
          source_ip: "any"
          traffic_type: "INPUT"
        - policy_name: "ipv4_telnet_http"
          index: 10
          destination_end_port: 389
          destination_ip: "any"
          destination_start_port: 389
          permission: "permit"
          protocol: "udp"
          source_ip: "any"
          traffic_type: "INPUT"

  - name: ipfilter policy is activated or active already
    brocade_security_ipfilter_policy:
      credential: "{{credential}}"
      vfid: -1
      active_policy: "ipv4_telnet_http"

"""


RETURN = """

msg:
    description: Success message
    returned: success
    type: str

"""


"""
Brocade Fibre Channel ipfilter rule configuration
"""


from ansible.module_utils.brocade_objects import list_helper
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
        ipfilter_rules=dict(required=True, type='list'))

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
    ipfilter_rules = input_params['ipfilter_rules']
    result = {"changed": False}

    list_helper(module, fos_ip_addr, fos_user_name, fos_password, https, True, throttle, vfid, "brocade_security", "ipfilter_rule", ipfilter_rules, False, result, timeout)


if __name__ == '__main__':
    main()
