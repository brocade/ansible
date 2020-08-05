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

module: brocade_list_obj_facts
short_description: Brocade generic facts gathering for list objects
version_added: '2.6'
author: Broadcom BSN Ansible Team <Automation.BSN@broadcom.com>
description:
- Gather FOS facts for objects that are defined as list in Yang

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
    module_name:
        description:
        - Yang module name. Hyphen or underscore are used interchangebly.
          If the Yang module name is xy-z, either xy-z or xy_z are acceptable.
        required: true
    obj_name:
        description:
        - Yang name for the list object. Hyphen or underscore are used
          interchangebly. If the Yang list name is xy-z, either
          xy-z or xy_z are acceptable.
        required: true
    attributes:
        description:
        - list of attributes for the object to match to return.
          names match Yang rest attributes with "-" replaced with "_".
          If none is given, the module returns all valid entries.
          Using hyphen in the name may result in errenously behavior
          based on Ansible parsing.

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

  - name: gather device info
    brocade_list_obj_facts:
      credential: "{{credential}}"
      vfid: -1
      module_name: "brocade-name-server"
      list_name: "fibrechannel-name-server"
      attributes:
        port_name: "{{wwn_to_search}}"

  - name: print ansible_facts gathered
    debug:
      var: ansible_facts

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
from ansible.module_utils.brocade_objects import list_get, to_human_list
from ansible.module_utils.brocade_yang import str_to_human, str_to_yang
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
        module_name=dict(required=True, type='str'),
        list_name=dict(required=True, type='str'),
        attributes=dict(required=False, type='dict'))

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
    module_name = str_to_human(input_params['module_name'])
    list_name = str_to_human(input_params['list_name'])
    attributes = input_params['attributes']
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

    ret_dict = {}
    ret_list = []
    for obj in obj_list:
        if attributes == None:
            ret_list.append(obj)
        else:
            matched_all = 0
            for k, v in attributes.items():
                if k in obj and obj[k] == v:
                    matched_all = matched_all + 1

            if matched_all == len(attributes.items()):
                ret_list.append(obj)

    if attributes == None:
        result["attributes_len"] = 0
    else:
        result["attributes_len"] = len(attributes.items())
    result["ret_list"] = ret_list

    ret_dict[list_name] = ret_list

    result["ansible_facts"] = ret_dict

    logout(fos_ip_addr, https, auth, result, timeout)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
