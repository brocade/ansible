#!/usr/bin/python

# Copyright 2019-2025 Broadcom. All rights reserved.
# The term 'Broadcom' refers to Broadcom Inc. and/or its subsidiaries.
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import (absolute_import, division, print_function)
__metaclass__ = type


DOCUMENTATION = '''

module: brocade_zoning_alias
short_description: Brocade Fibre Channel zoning alias configuration
version_added: '2.7'
author: Broadcom BSN Ansible Team <Automation.BSN@broadcom.com>
description:
- Create, detroy, or update aliases. The whole of aliases and
  aliases_to_delete are applied to FOS within a single login session
  to termininate after the completion. If no active cfg is found,
  cfgsave is executed before the completion of the session. If an
  active cfg is found, cfgenable of the existing cfg is executed
  to apply any potential changes before the completion of the session.

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
    aliases:
        description:
        - List of aliases to be created or modified. If an alias does
          not exist in the current Zone Database, the alias will be
          created with the members specified. If an alias already
          exist in the current Zone Database, the alias is updated to
          reflect to members specificed. In other word, new members
          will be added and removed members will be removed.
          If no aliases_to_delete are listed, aliases is required.
          aliases_to_delete and aliases are mutually exclusive.
        required: false
        type: list 
    members_add_only:
        description:
        - If set to True, new members will be added and old members
          not specified also remain.
        required: false
        type: bool
    members_remove_only:
        description:
        - If set to True, members specified are removed.
        required: false
        type: bool
    aliases_to_delete:
        description:
        - List of aliases to be deleted. If no aliases are listed,
          aliases_to_delete is required.  aliases_to_delete and
          aliases are mutually exclusive.
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
    aliases:
      - name: Host1
        members:
          - 11:22:33:44:55:66:77:88
      - name: Target1
        members:
          - 22:22:33:44:55:66:77:99      
      - name: Target2
        members:
          - 22:22:33:44:55:66:77:aa
      - name: Target3
        members:
          - 22:22:33:44:55:66:77:bb
    aliases_to_delete:
      - name: Target1
      - name: Target2
      - name: Target3

  tasks:

  - name: Create aliases
    brocade_zoning_alias:
      credential: "{{credential}}"
      vfid: -1
      aliases: "{{aliases}}"
      aliases_to_delete: "{{aliases_to_delete}}"

"""


RETURN = """

msg:
    description: Success message
    returned: success
    type: str

"""


"""
Brocade Fibre Channel zoning alias configuration
"""


from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.brocade_connection import login, logout, exit_after_login
from ansible.module_utils.brocade_zoning import zoning_common, alias_post, alias_delete, alias_get, alias_process_diff, alias_process_diff_to_delete


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
        aliases=dict(required=False, type='list'),
        members_add_only=dict(required=False, type='bool'),
        members_remove_only=dict(required=False, type='bool'),
        aliases_to_delete=dict(required=False, type='list'))

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
    aliases = input_params['aliases']
    members_add_only = input_params['members_add_only']
    members_remove_only = input_params['members_remove_only']
    aliases_to_delete = input_params['aliases_to_delete']
    result = {"changed": False}

    if vfid is None:
        vfid = 128

    ret_code, auth, fos_version = login(fos_ip_addr,
                           fos_user_name, fos_password,
                           https, throttle, result, timeout)
    if ret_code != 0:
        module.exit_json(**result)

    zoning_common(fos_ip_addr, https, fos_version, auth, vfid, result, module, aliases,
                  members_add_only, members_remove_only, aliases_to_delete, "alias",
                  alias_process_diff, alias_process_diff_to_delete,
                  alias_get, alias_post, alias_delete,
                  None, False, timeout)

    ret_code = logout(fos_ip_addr, https, auth, result, timeout)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
