#!/usr/bin/env python3

# Copyright 2019 Broadcom. All rights reserved.
# The term 'Broadcom' refers to Broadcom Inc. and/or its subsidiaries.
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import (absolute_import, division, print_function)
__metaclass__ = type


DOCUMENTATION = '''

module: brocade_fabric_switch_facts_by_pid
short_description: Brocade Fibre Channel switch find by connected device's pid
version_added: '2.7'
author: Broadcom BSN Ansible Team <Automation.BSN@broadcom.com>
description:
- Fibre Channel switch find by connected device's PID

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
        required: false
        type: int
    timeout:
        description:
        - REST timeout in seconds for operations that take longer than FOS
          default value.
        type: int
    pid:
        description:
        - Pid of the device
        required: true
        type: str

'''


EXAMPLES = """

  vars:
    credential:
      fos_ip_addr: "{{fos_ip_addr}}"
      fos_user_name: admin
      fos_password: xxxx
      https: False
    pid_to_search: "0x140000"

  tasks:

  - name: gather device alias info
    brocade_fabric_switch_facts_by_pid:
      credential: "{{credential}}"
      vfid: -1
      pid: "{{pid_to_search}}"

  - name: print fabric switch information matching pid
    debug:
      var: ansible_facts['fabric_switch']
    when: ansible_facts['fabric_switch'] is defined

"""


RETURN = """

msg:
    description: Success message
    returned: success
    type: str

"""


"""
Brocade fabric switch find by connected device's PID
"""


from ansible.module_utils.brocade_connection import login, logout, exit_after_login
from ansible.module_utils.brocade_yang import str_to_yang
from ansible.module_utils.brocade_objects import list_get, to_human_list
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
        pid=dict(required=True, type='str'))

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=False
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
    pid = input_params['pid']
    result = {"changed": False}

    if vfid is None:
        vfid = 128

    ret_code, auth, fos_version = login(fos_ip_addr,
                           fos_user_name, fos_password,
                           https, throttle, result, timeout)
    if ret_code != 0:
        module.exit_json(**result)

    facts = {}

    facts['ssh_hostkeymust'] = ssh_hostkeymust

    module_name = "brocade_fabric"
    list_name = "fabric_switch"

    ret_code, response = list_get(fos_user_name, fos_password, fos_ip_addr,
                                  module_name, list_name, fos_version,
                                  https, auth, vfid, result,
                                  ssh_hostkeymust, timeout)
    if ret_code != 0:
        result["list_get"] = ret_code
        exit_after_login(fos_ip_addr, https, auth, result, module, timeout)

    obj_list = response["Response"][str_to_yang(list_name)]
    if not isinstance(obj_list, list):
        if obj_list is None:
            obj_list = []
        else:
            obj_list = [obj_list]

    to_human_list(module_name, list_name, obj_list, result)

    result["obj_list"] = obj_list

    did = int(pid, 16) >> 16

    result["did"] = did

    ret_dict = {}

    for obj in obj_list:
        if obj["domain_id"] == str(did):
            ret_dict[list_name] = obj

    result["ansible_facts"] = ret_dict

    logout(fos_ip_addr, https, auth, result, timeout)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
