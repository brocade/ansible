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

module: brocade_list_obj
short_description: Brocade general list processing
version_added: '2.7'
author: Broadcom BSN Ansible Team <Automation.BSN@broadcom.com>
description:
- Update list of obj based on module name and list name provided

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
    module_name:
        description:
        - Yang module name. Hyphen or underscore are used interchangebly.
          If the Yang module name is xy-z, either xy-z or xy_z are acceptable.
        required: true
    list_name:
        description:
        - Yang name for the list object. Hyphen or underscore are used
          interchangebly. If the Yang list name is xy-z, either
          xy-z or xy_z are acceptable.
        required: true
    longer_timeout:
        description:
        - If the operation requires longer timeout
        required: false
    all_entries:
        description:
        - Boolean to indicate if the entries specified are full
          list of objects or not. By default, all_entries are
          thought to be true if not specified. If all_entries
          is set to true, the entries is used to calculate the change
          of existing entryies, addition, and deletion. If
          all_entries is set to false, the entries is used to
          calculate the change of existing entries only. i.e. 
          the module will not attempt to delete objects that do
          not show up in the entries and will not attempt to
          add objects that do show up in the entries but does
          not exist in FOS
        required: false
    entries:
        description:
        - List of objects. Name of each attributes within
          each entries should match the Yang name except hyphen
          is replaced with underscore. Using hyphen in the name
          may result in errenously behavior based on Ansible
          parsing.
        required: true

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

  - name: list object example
    brocade_list_obj:
      credential: "{{credential}}"
      vfid: -1
      module_name: "brocade-snmp"
      list_name: "v1-account"
      all_entries: False
      entries:
        - index: 1
          community_name: "new name"


"""


RETURN = """

msg:
    description: Success message
    returned: success
    type: str

"""


"""
Brocade Fibre Channel Yang list processor
"""


from ansible.module_utils.brocade_connection import login, logout, exit_after_login
from ansible.module_utils.brocade_yang import generate_diff, str_to_human, str_to_yang, is_full_human
from ansible.module_utils.brocade_objects import list_get, to_fos_list, to_human_list, list_entry_keys_matched, list_entry_keys, list_patch, list_post, list_delete
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
        list_name=dict(required=True, type='str'),
        all_entries=dict(required=False, type='bool'),
        longer_timeout=dict(required=False, type='int'),
        entries=dict(required=True, type='list'))

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
    module_name = str_to_human(input_params['module_name'])
    list_name = str_to_human(input_params['list_name'])
    entries = input_params['entries']
    all_entries = input_params['all_entries']
    longer_timeout = input_params['longer_timeout']
    result = {"changed": False}

    if not is_full_human(entries, result):
        module.exit_json(**result)

    if all_entries == None:
        result["all_entries_default"] = all_entries
        all_entries = True

    if vfid is None:
        vfid = 128

    ret_code, auth, fos_version = login(fos_ip_addr,
                           fos_user_name, fos_password,
                           https, throttle, result)
    if ret_code != 0:
        module.exit_json(**result)

    ret_code, response = list_get(fos_user_name, fos_password, fos_ip_addr,
                                  module_name, list_name, fos_version,
                                  https, auth, vfid, result,
                                  ssh_hostkeymust)
    if ret_code != 0:
        exit_after_login(fos_ip_addr, https, auth, result, module)

    current_entries = response["Response"][str_to_yang(list_name)]
    if not isinstance(current_entries, list):
        current_entries = [current_entries]

    to_human_list(module_name, list_name, current_entries, result)

    # for switch list object only, we only support one for now
    # and allow users to not specifcy the WWN of the switch
    # thus missing key of the entry. We'll get it from the switch
    if module_name == "brocade_fibrechannel_switch" and list_name == "fibrechannel_switch":
        if len(entries) != 1:
            result["failed"] = True
            result["msg"] = "Only one entry in an array is supported"
            exit_after_login(fos_ip_addr, https, auth, result, module)

        entries[0]["name"] = current_entries[0]["name"]

    diff_entries = []
    for entry in entries:
        for current_entry in current_entries:
            if list_entry_keys_matched(entry, current_entry, module_name, list_name):
                diff_attributes = generate_diff(result, current_entry, entry)
                if len(diff_attributes) > 0:
                    for key in list_entry_keys(module_name, list_name):
                        diff_attributes[key] = entry[key]
                    diff_entries.append(diff_attributes)

    ret_code = to_fos_list(module_name, list_name, diff_entries, result)
    result["diff_retcode"] = ret_code
    if ret_code != 0:
        exit_after_login(fos_ip_addr, https, auth, result, module)

    add_entries = []
    for entry in entries:

        # check to see if the new entry matches any of the old ones
        found = False
        for current_entry in current_entries:
            if list_entry_keys_matched(entry, current_entry, module_name, list_name):
                found = True
                break

        if not found:
            new_entry = {}
            for k, v in entry.items():
                new_entry[k] = v
            add_entries.append(new_entry)

    if module_name == "brocade_logging" and list_name == "syslog_server":
        new_add_entries = []
        for add_entry in add_entries:
            secured = ("secured_mode" in add_entry and add_entry["secured_mode"] == True)
            if not secured:
                new_add_entry = {}
                new_add_entry["server"] = add_entry["server"]
                new_add_entries.append(new_add_entry)
            else:
                new_add_entries.append(add_entry)
        add_entries = new_add_entries

    ret_code = to_fos_list(module_name, list_name, add_entries, result)
    result["add_retcode"] = ret_code
    if ret_code != 0:
        exit_after_login(fos_ip_addr, https, auth, result, module)

    delete_entries = []
    for current_entry in current_entries:
        found = False
        for entry in entries:
            if list_entry_keys_matched(entry, current_entry, module_name, list_name):
                found = True
                break

        if not found:
            delete_entry = {}
            for key in list_entry_keys(module_name, list_name):
                delete_entry[key] = current_entry[key]

            delete_entries.append(delete_entry)

    ret_code = to_fos_list(module_name, list_name, delete_entries, result)
    result["delete_retcode"] = ret_code
    if ret_code != 0:
        exit_after_login(fos_ip_addr, https, auth, result, module)

    result["response"] = response
    result["current_entries"] = current_entries
    result["diff_entries"] = diff_entries
    result["add_entries"] = add_entries
    result["delete_entries"] = delete_entries

    if len(diff_entries) > 0:
        if not module.check_mode:
            ret_code = 0
            if longer_timeout != None:
                ret_code = list_patch(fos_user_name, fos_password, fos_ip_addr, module_name, list_name, fos_version, https, auth, vfid, result, diff_entries, ssh_hostkeymust, longer_timeout)
            else:
                ret_code = list_patch(fos_user_name, fos_password, fos_ip_addr, module_name, list_name, fos_version, https, auth, vfid, result, diff_entries, ssh_hostkeymust)
            if ret_code != 0:
                exit_after_login(fos_ip_addr, https, auth, result, module)

        result["changed"] = True

    if len(add_entries) > 0 and all_entries:
        if not module.check_mode:
            ret_code = list_post(fos_user_name, fos_password, fos_ip_addr, module_name, list_name, fos_version, https, auth, vfid, result, add_entries, ssh_hostkeymust)
            if ret_code != 0:
                exit_after_login(fos_ip_addr, https, auth, result, module)

        result["changed"] = True

    if len(delete_entries) > 0 and all_entries:
        if not module.check_mode:
            ret_code = list_delete(fos_user_name, fos_password, fos_ip_addr, module_name, list_name, fos_version, https, auth, vfid, result, delete_entries, ssh_hostkeymust)
            if ret_code != 0:
                exit_after_login(fos_ip_addr, https, auth, result, module)

        result["changed"] = True

    logout(fos_ip_addr, https, auth, result)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
