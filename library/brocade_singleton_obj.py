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

module: brocade_singleton_obj
short_description: Brocade generic handler for singleton_obj
version_added: '2.7'
author: Broadcom BSN Ansible Team <Automation.BSN@broadcom.com>
description:
- userd for brocade-security/password object

options:

    credential:
        description:
        - login information including
          fos_ip_addr: ip address of the FOS switch
          fos_user_name: login name of FOS switch REST API
          fos_password: password of FOS switch REST API
          https: True for HTTPS, self for self-signed HTTPS, or False for HTTP
          ssh_hostkeymust: hostkeymust arguement for ssh attributes only. Default True.
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
    module_name:
        description:
        - name of module. for example, brocade-security
    obj_name:
        description:
        - name of obj. for example, password under brocade-security
    attributes:
        description:
        - list of attributes for the object. names match rest attributes
          with "-" replaced with "_"
          - special node for "brocade-security" module "password" object
            "old_password" and "new_password" are in plain text
            if "user_name" is user account, only "new_password" is needed

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
Brocade Fibre Channel switch Configuration
"""


from ansible.module_utils.brocade_connection import login, logout, exit_after_login
from ansible.module_utils.brocade_yang import generate_diff
from ansible.module_utils.brocade_objects import singleton_patch, singleton_get, to_human_singleton, to_fos_singleton
from ansible.module_utils.basic import AnsibleModule


def main():
    """
    Main function
    """

    argument_spec = dict(
        credential=dict(required=True, type='dict', no_log=True),
        vfid=dict(required=False, type='int'),
        throttle=dict(required=False, type='float'),
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
    vfid = input_params['vfid']
    module_name = input_params['module_name']
    obj_name = input_params['obj_name']
    attributes = input_params['attributes']
    result = {"changed": False}

    if vfid is None:
        vfid = 128

    ret_code, auth, fos_version = login(fos_ip_addr,
                           fos_user_name, fos_password,
                           https, throttle, result)
    if ret_code != 0:
        module.exit_json(**result)

    result['ssh_hostkeymust'] = ssh_hostkeymust

    ret_code, response = singleton_get(fos_user_name, fos_password, fos_ip_addr,
                                       module_name, obj_name, fos_version,
                                       https, auth, vfid, result,
                                       ssh_hostkeymust)
    if ret_code != 0:
        exit_after_login(fos_ip_addr, https, auth, result, module)

    resp_attributes = response["Response"][obj_name]

    to_human_singleton(module_name, obj_name, resp_attributes)

    diff_attributes = generate_diff(result, resp_attributes, attributes)

    # any object specific special processing
    if module_name == "brocade-maps" and obj_name == "maps-config":
        # relay_ip_address and domain_name needs to be specifid
        # at the same time based on FOS REST requirements
        if "relay_ip_address" in diff_attributes and "domain_name" not in diff_attributes:
            diff_attributes["domain_name"] = resp_attributes["domain_name"]
            result["kept the same"] = "domain_name"
        elif "relay_ip_address" not in diff_attributes and "domain_name" in diff_attributes:
            diff_attributes["relay_ip_address"] = resp_attributes["relay_ip_address"]
            result["kept the same"] = "relay_ip_address"

        if "relay_ip_address" in diff_attributes and diff_attributes["relay_ip_address"] == None:
            result["failed"] = True
            result['msg'] = "must specify relay_ip_address if configured empty"
            exit_after_login(fos_ip_addr, https, auth, result, module)
        elif "domain_name" in diff_attributes and diff_attributes["domain_name"] == None:
            result["failed"] = True
            result['msg'] = "must specify domain_name if configured empty"
            exit_after_login(fos_ip_addr, https, auth, result, module)

    result["diff_attributes"] = diff_attributes
    result["resp_attributes"] = resp_attributes
    result["attributes"] = attributes

    if len(diff_attributes) > 0:
        ret_code = to_fos_singleton(module_name, obj_name, diff_attributes, result)
        if ret_code != 0:
            exit_after_login(fos_ip_addr, https, auth, result, module)

        if not module.check_mode:
            ret_code = singleton_patch(fos_user_name, fos_password, fos_ip_addr,
                                       module_name, obj_name,
                                       fos_version, https,
                                       auth, vfid, result, diff_attributes,
                                       ssh_hostkeymust)
            if ret_code != 0:
                exit_after_login(fos_ip_addr, https, auth, result, module)

        result["changed"] = True
    else:
        logout(fos_ip_addr, https, auth, result)
        module.exit_json(**result)

    logout(fos_ip_addr, https, auth, result)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
