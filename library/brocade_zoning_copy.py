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

module: brocade_zoning_copy
short_description: Brocade Zoning object copy
version_added: '2.7'
author: Broadcom BSN Ansible Team <Automation.BSN@broadcom.com>
description:
- Mimics zoneObjectCopy funcionalities. The module is used to
  confirm that an existing object's and the new object's contents
  match. If they do not, the new object may be created or
  overwritten to match the contents.
  
  If an existing object is Target Driven Zone, the module
  will error out. If objects do not match in terms of type (Alias,
  Zone, or CFG), the module will error out.

options:

    credential:
        description:
        - login information including
          fos_ip_addr - ip address of the FOS switch
          fos_user_name - login name of FOS switch REST API
          fos_password - password of FOS switch REST API
          https - True for HTTPS, self for self-signed HTTPS, or False for HTTP
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
    object_name:
        description:
        - Name of the object to copy from.
        required: true
    new_name:
        description:
        - Name of the object to copy to.
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

  - name: copy Alias
    brocade_zoning_copy:
      credential: "{{credential}}"
      vfid: -1
      object_name: old_alias
      new_name: new_alias

"""


RETURN = """

msg:
    description: Success message
    returned: success
    type: str

"""


"""
Brocade Zoning Zones
"""


from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.brocade_connection import login, logout, exit_after_login
from ansible.module_utils.brocade_zoning import zoning_common, zone_post, zone_delete, zone_get, process_member_diff, zoning_find_pair_common, alias_post, alias_delete, alias_get, alias_process_diff, alias_process_diff_to_delete, zone_process_diff, zone_process_diff_to_delete, cfg_post, cfg_delete, cfg_get, cfg_process_diff, cfg_process_diff_to_delete


def main():
    """
    Main function
    """

    argument_spec = dict(
        credential=dict(required=True, type='dict', no_log=True),
        vfid=dict(required=False, type='int'),
        throttle=dict(required=False, type='float'),
        timeout=dict(required=False, type='float'),
        object_name=dict(required=True, type='str'),
        new_name=dict(required=True, type='str'))

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
    object_name = input_params['object_name']
    new_name = input_params['new_name']
    result = {"changed": False}

    if vfid is None:
        vfid = 128

    ret_code, auth, fos_version = login(fos_ip_addr,
                           fos_user_name, fos_password,
                           https, throttle, result, timeout)
    if ret_code != 0:
        module.exit_json(**result)

    object_name_dict, new_name_dict = zoning_find_pair_common(module, fos_ip_addr, https, auth, vfid, "alias", object_name, new_name, result, timeout)

    result["object_name_dict"] = object_name_dict
    result["new_name_dict"] = new_name_dict

    # object_name was found and new_name doesn't exist. Create one
    if len(object_name_dict) > 0:
        object_name_dict["name"] = new_name
        obj_list = [object_name_dict]
        zoning_common(fos_ip_addr, https, auth, vfid, result, module, obj_list,
                  False, False, None, "alias",
                  alias_process_diff, alias_process_diff_to_delete, alias_get,
                  alias_post, alias_delete, None, timeout)
        ret_code = logout(fos_ip_addr, https, auth, result, timeout)
        module.exit_json(**result)

    object_name_dict, new_name_dict = zoning_find_pair_common(module, fos_ip_addr, https, auth, vfid, "zone", object_name, new_name, result, timeout)

    result["object_name_dict"] = object_name_dict
    result["new_name_dict"] = new_name_dict

    # object_name was found and new_name doesn't exist. Create one
    if len(object_name_dict) > 0:
        if object_name_dict["zone-type"] == 2:
            result["failed"] = True
            result["msg"] = "Target created Peer Zone cannot be copied"
            ret_code = logout(fos_ip_addr, https, auth, result, timeout)
            module.exit_json(**result)

        object_name_dict["name"] = new_name
        obj_list = [object_name_dict]
        zoning_common(fos_ip_addr, https, auth, vfid, result, module, obj_list,
                  False, False, None, "zone",
                  zone_process_diff, zone_process_diff_to_delete, zone_get,
                  zone_post, zone_delete, None, timeout)
        ret_code = logout(fos_ip_addr, https, auth, result, timeout)
        module.exit_json(**result)

    object_name_dict, new_name_dict = zoning_find_pair_common(module, fos_ip_addr, https, auth, vfid, "cfg", object_name, new_name, result, timeout)

    result["object_name_dict"] = object_name_dict
    result["new_name_dict"] = new_name_dict

    # object_name was found and new_name doesn't exist. Create one
    if len(object_name_dict) > 0:
        object_name_dict["name"] = new_name
        obj_list = [object_name_dict]
        zoning_common(fos_ip_addr, https, auth, vfid, result, module, obj_list,
                  False, False, None, "cfg",
                  cfg_process_diff, cfg_process_diff_to_delete, cfg_get,
                  cfg_post, cfg_delete, None, timeout)
        ret_code = logout(fos_ip_addr, https, auth, result, timeout)
        module.exit_json(**result)

    
    result["failed"] = True
    result["msg"] = "no such object was found"
    ret_code = logout(fos_ip_addr, https, auth, result, timeout)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
