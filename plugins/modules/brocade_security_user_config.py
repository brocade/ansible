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
- Update security user config configuration

options:

    credential:
        description:
        - login information including
          fos_ip_addr: ip address of the FOS switch
          fos_user_name: login name of FOS switch REST API
          fos_password: password of FOS switch REST API
          https: indicate if HTTPS or HTTP should be used to connect to FOS
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
            - role_id: "admin=1-128"
          chassis_access_role: "admin"
        - name: "youraccount"
          password: "bXlwYXNzd29yZA=="
          virtual_fabric_role_id_list:
            - role_id: "admin=1-128"
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


from ansible.module_utils.brocade_connection import login, logout, exit_after_login
from ansible.module_utils.brocade_yang import generate_diff
from ansible.module_utils.brocade_security import user_config_patch, user_config_post, user_config_delete, user_config_get, to_human_user_config, to_fos_user_config
from ansible.module_utils.basic import AnsibleModule


def main():
    """
    Main function
    """

    argument_spec = dict(
        credential=dict(required=True, type='dict'),
        vfid=dict(required=False, type='int'),
        throttle=dict(required=False, type='float'),
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
    throttle = input_params['throttle']
    vfid = input_params['vfid']
    user_configs = input_params['user_configs']
    delete_user_configs = input_params['delete_user_configs']
    result = {"changed": False}

    if vfid is None:
        vfid = 128

    ret_code, auth, fos_version = login(fos_ip_addr,
                           fos_user_name, fos_password,
                           https, throttle, result)
    if ret_code != 0:
        module.exit_json(**result)

    ret_code, response = user_config_get(
        fos_ip_addr, https, auth, vfid, result)
    if ret_code != 0:
        exit_after_login(fos_ip_addr, https, auth, result, module)

    resp_uc = response["Response"]["user-config"]

    if isinstance(resp_uc, list):
        c_user_configs = resp_uc
    else:
        c_user_configs = [resp_uc]

    for c_user_config in c_user_configs:
        if not isinstance(c_user_config["virtual-fabric-role-id-list"], list):
            c_user_config["virtual-fabric-role-id-list"] = [c_user_config["virtual-fabric-role-id-list"]]

    # convert REST to human readable format first
    for c_user_config in c_user_configs:
        to_human_user_config(c_user_config)

    # if delete user config is not None, then we make sure
    # the user config is not present.
    # user config creation or update does not happen at the same
    # time
    if delete_user_configs != None:
        to_delete = []
        for delete_user_config in delete_user_configs:
            found = False
            for c_user_config in c_user_configs:
                if c_user_config["name"] == delete_user_config["name"]:
                    found = True
                    break
            if found:
                to_delete.append(delete_user_config)

        if len(to_delete) > 0:
            if not module.check_mode:
                ret_code = user_config_delete(
                    fos_ip_addr, https,
                    auth, vfid, result, to_delete)
                if ret_code != 0:
                    exit_after_login(fos_ip_addr, https, auth, result, module)

            result["changed"] = True

        logout(fos_ip_addr, https, auth, result)
        module.exit_json(**result)

    diff_user_configs = []
    for new_uc in user_configs:
        for c_user_config in c_user_configs:
            if new_uc["name"] == c_user_config["name"]:
                diff_attributes = generate_diff(result, c_user_config, new_uc)
                # cannot change password using patch
                # so skip for diff identification
                if "password" in diff_attributes:
                    diff_attributes.pop("password")

                if len(diff_attributes) > 0:
                    result["c_user_config"] = c_user_config
                    diff_attributes["name"] = new_uc["name"]
                    ret_code = to_fos_user_config(diff_attributes, result)
                    if ret_code != 0:
                        exit_after_login(fos_ip_addr, https, auth, result, module)

                    diff_user_configs.append(diff_attributes)

    add_user_configs = []
    for new_uc in user_configs:
        found = False
        for c_user_config in c_user_configs:
            if new_uc["name"] == c_user_config["name"]:
                found = True
        if not found:
            new_user_config = {}
            for k, v in new_uc.items():
                new_user_config[k] = v
            ret_code = to_fos_user_config(new_user_config, result)
            result["retcode"] = ret_code
            if ret_code != 0:
                exit_after_login(fos_ip_addr, https, auth, result, module)

            add_user_configs.append(new_user_config)

    result["resp_uc"] = resp_uc
    result["user_configs"] = user_configs
    result["diff_user_configs"] = diff_user_configs
    result["add_user_configs"] = add_user_configs

    if len(diff_user_configs) > 0:
        if not module.check_mode:
            ret_code = user_config_patch(
                fos_user_name, fos_password,
                fos_ip_addr, fos_version, https,
                auth, vfid, result, diff_user_configs)
            if ret_code != 0:
                exit_after_login(fos_ip_addr, https, auth, result, module)

        result["changed"] = True

    if len(add_user_configs) > 0:
        if not module.check_mode:
            ret_code = user_config_post(
                fos_ip_addr, https,
                auth, vfid, result, add_user_configs)
            if ret_code != 0:
                exit_after_login(fos_ip_addr, https, auth, result, module)

        result["changed"] = True

    logout(fos_ip_addr, https, auth, result)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
