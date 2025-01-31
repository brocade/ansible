#!/usr/bin/python

# Copyright 2025 Broadcom. All rights reserved.
# The term 'Broadcom' refers to Broadcom Inc. and/or its subsidiaries.
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import (absolute_import, division, print_function)
__metaclass__ = type


DOCUMENTATION = '''

module: brocade_operation
short_description: Brocade IPS operations
version_added: '2.7'
author: Broadcom BSN Ansible Team <Automation.BSN@broadcom.com>
description:
- Perform IPS operations for list of objects based on module name and list name provided

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
    module_name:
        description:
        - Yang module name. Hyphen or underscore are used interchangebly.
          If the Yang module name is xy-z, either xy-z or xy_z are acceptable.
        required: true
        type: str
    list_name:
        description:
        - Yang name for the list object. Hyphen or underscore are used
          interchangebly. If the Yang list name is xy-z, either
          xy-z or xy_z are acceptable.
        required: true
        type: str
    all_entries:
        description:
        - Boolean to indicate if the entries specified are full
          list of objects or not. By default, all_entries are
          thought to be true if not specified. If all_entries
          is set to true, the entries is used to calculate the change
          of existing entryies, addition, and deletion. If
          all_entries is set to false, the entries is used to
          calculate the change of existing entries and addition
          of entries only. i.e.  the module will not attempt to
          delete objects that do not show up in the entries.
        required: false
        type: bool
    entries:
        description:
        - List of objects. Name of each attributes within
          each entries should match the Yang name except hyphen
          is replaced with underscore. Using hyphen in the name
          may result in errenously behavior based on Ansible
          parsing.
        required: true
        type: list

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
from ansible.module_utils.brocade_objects import list_get, to_fos_list, to_human_list, list_entry_keys_matched, list_entry_keys, list_patch, list_post, list_delete, list_operation_helper
from ansible.module_utils.basic import AnsibleModule

def main():
    """
    Main function
    """

    argument_spec = dict(
        credential=dict(required=True, type='dict', options=dict(
            fos_ip_addr=dict(required=True, type='str'),
            fos_user_name=dict(required=True, type='str'),
            fos_password=dict(required=True, type='str', no_log=True),
            https=dict(required=True, type='str'),
            ssh_hostkeymust=dict(required=False, type='bool'))),
        vfid=dict(required=False, type='int'),
        throttle=dict(required=False, type='int'),
        timeout=dict(required=False, type='int'),
        module_name=dict(required=True, type='str'),
        entries=dict(required=True, type='list'),
        all_entries=dict(required=False, type='bool'))

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
    timeout = input_params['timeout']
    vfid = input_params['vfid']
    entries = input_params['entries']
    all_entries = input_params['all_entries']
    result = {"changed": False}
    module_name = input_params['module_name']
    list_name = ""

    if module_name == "vrf":
        module_name = "ipStorage"
        list_name =  "vrf"
    elif module_name == "vlan":
        module_name = "ipStorage"
        list_name =  "vlan"
    elif module_name == "interface":
        module_name = "ipStorage"
        list_name =  "interface"
    elif module_name == "staticArp":
        module_name = "ipStorage"
        list_name =  "staticArp"
    elif module_name == "staticRoute":
        module_name = "ipStorage"
        list_name =  "staticRoute"
    elif module_name == "lag":
        module_name = "ipStorage"
        list_name =  "lag"
    elif module_name == "configuration":
        module_name = "trafficClass"
        list_name =  "configuration"

    list_operation_helper(module, fos_ip_addr, fos_user_name, fos_password, https, ssh_hostkeymust, throttle, vfid, module_name, list_name, entries, all_entries, result, timeout)


if __name__ == '__main__':
    main()
