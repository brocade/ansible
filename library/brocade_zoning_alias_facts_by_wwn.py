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

module: brocade_facts
short_description: Brocade facts gathering of Zoning by WWN
version_added: '2.6'
author: Broadcom BSN Ansible Team <Automation.BSN@broadcom.com>
description:
- Gather FOS facts

options:

    credential:
        description:
        - login information including
          fos_ip_addr - ip address of the FOS switch
          fos_user_name - login name of FOS switch REST API
          fos_password - password of FOS switch REST API
          https - True for HTTPS, self for self-signed HTTPS, or False for HTTP
          ssh_hostkeymust - hostkeymust arguement for ssh attributes only. Default True.
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
    wwn:
        description:
        - wwn to search in the aliases within Zone DB
        required: true

'''


EXAMPLES = """

  var:
    credential:
      fos_ip_addr: "{{fos_ip_addr}}"
      fos_user_name: admin
      fos_password: fibranne
      https: False
    wwn_to_search: "11:22:33:44:55:66:77:88"

  tasks:

  - name: gather device alias info
    brocade_zoning_alias_facts_by_wwn:
      credential: "{{credential}}"
      vfid: -1
      wwn: "{{wwn_to_search}}"

  - name: print device alias information matching port_name
    debug:
      var: ansible_facts['alias']
    when: ansible_facts['alias'] is defined

"""


RETURN = """

msg:
    description: Success message
    returned: success
    type: str

"""


"""
Brocade Fibre Channel Port Configuration
"""


from ansible.module_utils.brocade_connection import login, logout, exit_after_login
from ansible.module_utils.brocade_zoning import defined_get
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
        wwn=dict(required=True, type='str'))

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
    wwn = input_params['wwn']
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

    ret_code, response = defined_get(fos_ip_addr, https, auth, vfid, result, timeout)
    if ret_code != 0:
        exit_after_login(fos_ip_addr, https, auth, result, module)

    if ret_code != 0:
        exit_after_login(fos_ip_addr, https, auth, result, module)

    alias_list = []
    if "alias" in response["Response"]["defined-configuration"]:
        if isinstance(response["Response"]["defined-configuration"]["alias"], list):
            alias_list = response["Response"]["defined-configuration"]["alias"]
        else:
            alias_list = [response["Response"]["defined-configuration"]["alias"]]

    result["alias_list"] = alias_list

    ret_list = []
    for alias in alias_list:
        if "member-entry" in alias and "alias-entry-name" in alias["member-entry"]:
            if isinstance(alias["member-entry"]["alias-entry-name"], list):
                for entry in alias["member-entry"]["alias-entry-name"]:
                    if entry == wwn.lower():
                        ret_list.append(alias)
                        break
            else:
                if alias["member-entry"]["alias-entry-name"] == wwn.lower():
                    ret_list.append(alias)

    ret_dict = {}
    if len(ret_list) > 0:
        ret_dict["alias"] = ret_list

    result["ansible_facts"] = ret_dict

    logout(fos_ip_addr, https, auth, result, timeout)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
