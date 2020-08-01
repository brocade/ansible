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

module: brocade_singleton_obj_facts
short_description: Brocade generic facts gathering for singleton objects
version_added: '2.6'
author: Broadcom BSN Ansible Team <Automation.BSN@broadcom.com>
description:
- Gather FOS facts for singleon obj

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
        - Yang name for the object. Hyphen or underscore are used
          interchangebly. If the Yang list name is xy-z, either
          xy-z or xy_z are acceptable.
        required: true

'''


EXAMPLES = """

  var:
    credential:
      fos_ip_addr: "{{fos_ip_addr}}"
      fos_user_name: admin
      fos_password: fibranne
      https: False

  tasks:

  - name: gather device info
    brocade_list_obj_facts:
      credential: "{{credential}}"
      vfid: -1
      module_name: "brocade-snmp"
      obj_name: "system"

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
from ansible.module_utils.brocade_objects import singleton_get, to_human_singleton
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
        obj_name=dict(required=True, type='str'))

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
    obj_name = str_to_human(input_params['obj_name'])
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

    ret_code, response = singleton_get(fos_user_name, fos_password, fos_ip_addr,
                                  module_name, obj_name, fos_version,
                                  https, auth, vfid, result,
                                  ssh_hostkeymust, timeout)
    if ret_code != 0:
        result["singleton_get"] = ret_code
        exit_after_login(fos_ip_addr, https, auth, result, module, timeout)

    obj = response["Response"][str_to_yang(obj_name)]

    to_human_singleton(module_name, obj_name, obj)

    result["obj"] = obj

    ret_dict = {}
    ret_dict[obj_name] = obj

    result["ansible_facts"] = ret_dict

    logout(fos_ip_addr, https, auth, result, timeout)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
