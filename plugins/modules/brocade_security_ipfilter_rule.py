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

module: brocade_security_ipfilter_rule
short_description: Brocade security ipfilter rule Configuration
version_added: '2.7'
author: Broadcom BSN Ansible Team <Automation.BSN@broadcom.com>
description:
- Update secuirty ipfilter rule configuration

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
    ipfilter_rules:
        description:
        - list of ipfilter rules data structure
          All writable attributes supported
          by BSN REST API with - replaced with _.
        required: true

'''


EXAMPLES = """

  gather_facts: False

  vars:
    credential:
      fos_ip_addr: "{{fos_ip_addr}}"
      fos_user_name: admin
      fos_password: fibranne
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
Brocade Fibre Channel ipfilter rule Configuration
"""


from ansible_collections.daniel_chung_broadcom.fos.plugins.module_utils.brocade_connection import login, logout, exit_after_login
from ansible_collections.daniel_chung_broadcom.fos.plugins.module_utils.brocade_yang import generate_diff
from ansible_collections.daniel_chung_broadcom.fos.plugins.module_utils.brocade_security import ipfilter_rule_patch, ipfilter_rule_post, ipfilter_rule_delete, ipfilter_rule_get, to_human_ipfilter_rule, to_fos_ipfilter_rule
from ansible.module_utils.basic import AnsibleModule


def main():
    """
    Main function
    """

    argument_spec = dict(
        credential=dict(required=True, type='dict', no_log=True),
        vfid=dict(required=False, type='int'),
        throttle=dict(required=False, type='float'),
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
    vfid = input_params['vfid']
    ipfilter_rules = input_params['ipfilter_rules']
    result = {"changed": False}

    if vfid is None:
        vfid = 128

    ret_code, auth, fos_version = login(fos_ip_addr,
                           fos_user_name, fos_password,
                           https, throttle, result)
    if ret_code != 0:
        module.exit_json(**result)

    ret_code, response = ipfilter_rule_get(
        fos_ip_addr, https, auth, vfid, result)
    if ret_code != 0:
        exit_after_login(fos_ip_addr, https, auth, result, module)

    resp_ir = response["Response"]["ipfilter-rule"]

    if isinstance(resp_ir, list):
        c_rules = resp_ir
    else:
        c_rules = [resp_ir]

    # convert everything to human readable from REST
    for c_rule in c_rules:
        to_human_ipfilter_rule(c_rule)

    diff_rules = []
    for new_ir in ipfilter_rules:
        for c_rule in c_rules:
            if new_ir["policy_name"] == c_rule["policy_name"] and str(new_ir["index"]) == c_rule["index"]:
                diff_attributes = generate_diff(result, c_rule, new_ir)
                if len(diff_attributes) > 0:
                    result["c_rule"] = c_rule
                    diff_attributes["policy_name"] = new_ir["policy_name"]
                    diff_attributes["index"] = new_ir["index"]
                    ret_code = to_fos_ipfilter_rule(diff_attributes, result)
                    result["retcode"] = ret_code
                    if ret_code != 0:
                        exit_after_login(fos_ip_addr, https, auth, result, module)

                    diff_rules.append(diff_attributes)

    add_rules = []
    for new_ir in ipfilter_rules:
        found = False
        for c_rule in c_rules:
            if new_ir["policy_name"] == c_rule["policy_name"] and str(new_ir["index"]) == c_rule["index"]:
                found = True
        if not found:
            new_yang_rule = {}
            for k, v in new_ir.items():
                new_yang_rule[k] = v
            ret_code = to_fos_ipfilter_rule(new_yang_rule, result)
            result["retcode"] = ret_code
            if ret_code != 0:
                exit_after_login(fos_ip_addr, https, auth, result, module)

            add_rules.append(new_yang_rule)

    delete_rules = []
    for c_rule in c_rules:
        found = False
        for new_ir in ipfilter_rules:
            if new_ir["policy_name"] == c_rule["policy_name"] and str(new_ir["index"]) == c_rule["index"]:
                found = True
        if not found:
            delete_rule = {}
            delete_rule["policy-name"] = c_rule["policy_name"]
            delete_rule["index"] = c_rule["index"]
            delete_rules.append(delete_rule)

    result["resp_ir"] = resp_ir
    result["ipfilter_rules"] = ipfilter_rules
    result["diff_rules"] = diff_rules
    result["add_rules"] = add_rules
    result["delete_rules"] = delete_rules

    if len(diff_rules) > 0:
        if not module.check_mode:
            ret_code = ipfilter_rule_patch(
                fos_ip_addr, https,
                auth, vfid, result, diff_rules)
            if ret_code != 0:
                exit_after_login(fos_ip_addr, https, auth, result, module)

        result["changed"] = True

    if len(add_rules) > 0:
        if not module.check_mode:
            ret_code = ipfilter_rule_post(
                fos_ip_addr, https,
                auth, vfid, result, add_rules)
            if ret_code != 0:
                exit_after_login(fos_ip_addr, https, auth, result, module)

        result["changed"] = True

#    if len(delete_rules) > 0:
#        if not module.check_mode:
#            ret_code = ipfilter_rule_delete(
#                fos_ip_addr, https,
#                auth, vfid, result, delete_rules)
#            if ret_code != 0:
#                exit_after_login(fos_ip_addr, https, auth, result, module)
#
#        result["changed"] = True

    logout(fos_ip_addr, https, auth, result)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
