#!/usr/bin/env python3

# Copyright 2019 Broadcom. All rights reserved.
# The term 'Broadcom' refers to Broadcom Inc. and/or its subsidiaries.
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import (absolute_import, division, print_function)
__metaclass__ = type


DOCUMENTATION = '''

module: brocade_security_ipfilter_policy
short_description: Brocade Fibre Channel security ipfilter policy configuration
version_added: '2.7'
author: Broadcom BSN Ansible Team <Automation.BSN@broadcom.com>
description:
- Update Fibre Channel security ipfilter policy configuration

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
    ipfilter_policies:
        description:
        - List of ipfilter policies data structure.
          All writable attributes supported
          by BSN REST API with - replaced with _.
        required: false
        type: list
    active_policy:
        description:
        - Name of the active policy. Mutually exclusive
          with ipfilter_policies and delete_policy.
          This shoud come after policies are created and
          filled with rules
        required: false
        type: str
    delete_policies:
        description:
        - Name of the policy to be deleted. Mutually exclusive
          with ipfilter_policies and active_policy.
        required: false
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

  - name: activate default ipv4 before deleting previously created custom policy
    brocade_security_ipfilter_policy:
      credential: "{{credential}}"
      vfid: -1
      active_policy: "default_ipv4"

  - name: delete custom policy
    brocade_security_ipfilter_policy:
      credential: "{{credential}}"
      vfid: -1
      delete_policies:
        - name: "ipv4_telnet_http"

"""


RETURN = """

msg:
    description: Success message
    returned: success
    type: str

"""


"""
Brocade Fibre Channel ipfilter policy Configuration
"""


from ansible.module_utils.brocade_connection import login, logout, exit_after_login
from ansible.module_utils.brocade_yang import is_full_human
from ansible.module_utils.brocade_objects import list_helper, list_delete_helper
from ansible.module_utils.brocade_security import ipfilter_policy_patch, ipfilter_policy_get, to_human_ipfilter_policy, to_fos_ipfilter_policy
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
        ipfilter_policies=dict(required=False, type='list'),
        active_policy=dict(required=False, type='str'),
        delete_policies=dict(required=False, type='list'))

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
    ipfilter_policies = input_params['ipfilter_policies']
    active_policy = input_params['active_policy']
    delete_policies = input_params['delete_policies']
    result = {"changed": False}

    # if delete policy is not None, then we make sure
    # the policy is not present.
    # policy creation or update does not happen at the same
    # time
    if delete_policies != None:
        return list_delete_helper(module, fos_ip_addr, fos_user_name, fos_password, https, True, throttle, vfid, "brocade_security", "ipfilter_policy", delete_policies, True, result, timeout)

    # if I am dealing with active_policy set, it must be policy list update
    if active_policy == None:
        return list_helper(module, fos_ip_addr, fos_user_name, fos_password, https, True, throttle, vfid, "brocade_security", "ipfilter_policy", ipfilter_policies, False, result, timeout)

    if not is_full_human(ipfilter_policies, result):
        module.exit_json(**result)

    if vfid is None:
        vfid = 128

    ret_code, auth, fos_version = login(fos_ip_addr,
                           fos_user_name, fos_password,
                           https, throttle, result, timeout)
    if ret_code != 0:
        module.exit_json(**result)

    ret_code, response = ipfilter_policy_get(
        fos_ip_addr, https, auth, vfid, result, timeout)
    if ret_code != 0:
        exit_after_login(fos_ip_addr, https, auth, result, module, timeout)

    resp_ir = response["Response"]["ipfilter-policy"]

    if isinstance(resp_ir, list):
        c_policies = resp_ir
    else:
        c_policies = [resp_ir]

    # convert REST to human readable format first
    for c_policy in c_policies:
        to_human_ipfilter_policy(c_policy)

    # if active policy is not None, then we make sure
    # the policy is active or activate. and return
    # policy creation or update does not happen at the same
    # time
    if active_policy != None:
        found_disabled_policy = False
        found_active_policy = False
        activate_list = []
        for c_policy in c_policies:
            if c_policy["name"] == active_policy:
                if c_policy["is_policy_active"] == False:
                    found_disabled_policy = True
                    activate_dict = {
                        "name": c_policy["name"],
                        "action": "activate"
                        }
                    activate_list.append(activate_dict)
                else:
                    found_active_policy = True
                    activate_dict = {
                        "name": c_policy["name"],
                        }
                    activate_list.append(activate_dict)

        if found_disabled_policy:
            if not module.check_mode:
                ret_code = ipfilter_policy_patch(
                    fos_ip_addr, https,
                    auth, vfid, result, activate_list, timeout)
                if ret_code != 0:
                    exit_after_login(fos_ip_addr, https, auth, result, module, timeout)

            result["changed"] = True
        elif found_active_policy:
            result["same active policy"] = activate_list
        else:
            result["failed"] = True
            result["msg"] = "could not find matching policy"

        logout(fos_ip_addr, https, auth, result, timeout)
        module.exit_json(**result)


if __name__ == '__main__':
    main()
