#!/usr/bin/python

# Copyright 2024 Broadcom. All rights reserved.
# The term 'Broadcom' refers to Broadcom Inc. and/or its subsidiaries.
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import (absolute_import, division, print_function)
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.brocade.fos.plugins.module_utils.brocade_yang import str_to_yang, str_to_human
from ansible_collections.brocade.fos.plugins.module_utils.brocade_objects import list_get, to_human_list
from ansible_collections.brocade.fos.plugins.module_utils.brocade_connection import login, logout, exit_after_login

__metaclass__ = type


DOCUMENTATION = '''

module: brocade_ips_facts
short_description: Brocade IP storage facts gathering
version_added: '1.0'
author: Broadcom BSN Ansible Team <Automation.BSN@broadcom.com>
description:
- Gather IPS facts

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
    gather_subset:
        description:
        - List of areas to be gathered. If this option is missing,
          all areas' facts will be gathered. Same behavior applies
          if "all" is listed as part of gather_subset.
        choices:
            - all
            - vrf
            - vlan            
            - staticArp            
            - staticRoute            
            - lag
            - configuration            
            - interface
            - arpTable
            - routeTable
        required: false
        default: all
        type: list

'''


EXAMPLES = """

  vars:
    credential:
      fos_ip_addr: "{{fos_ip_addr}}"
      fos_user_name: admin
      fos_password: password
      https: self

  tasks:

  - name: gather facts
    brocade_ips_facts:
      credential: "{{credential}}"
      vfid: "{{ips_fid}}"
      gather_subset:        
        - vrf
        - vlan            
        - staticArp            
        - staticRoute            
        - lag
        - configuration            
        - interface
        - arpTable
        - routeTable

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
Brocade IP Storage gather facts
"""


valid_areas = [
    "vrf",
    "vlan",
    "staticArp",
    "staticRoute",
    "lag",
    "configuration",
    "interface",
    "arpTable",
    "routeTable",
]


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
        gather_subset=dict(required=True, type='list'))

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
    gather_subset = input_params['gather_subset']
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

    if gather_subset is not None:
        for subset in gather_subset:
            if subset != "all" and subset not in valid_areas:
                result["failed"] = True
                result["msg"] = "Request for unknown module and object " + subset
                logout(fos_ip_addr, https, auth, result, timeout)
                module.exit_json(**result)

    for area in valid_areas:
        if (gather_subset is None or area in gather_subset or "all" in gather_subset):
            get_list = True
            module_name = ""

            if area == "vrf":
                module_name = "ipstorage"
                list_name = "vrf"
                get_list = True
            elif area == "vlan":
                module_name = "ipstorage"
                list_name = "vlan"
                get_list = True
            elif area == "staticArp":
                module_name = "ipstorage"
                list_name = "staticArp"
                get_list = True
            elif area == "staticRoute":
                module_name = "ipstorage"
                list_name = "staticRoute"
                get_list = True
            elif area == "lag":
                module_name = "ipstorage"
                list_name = "lag"
                get_list = True
            elif area == "configuration":
                module_name = "trafficClass"
                list_name = "configuration"
                get_list = True
            elif area == "interface":
                module_name = "ipstorage"
                list_name = "interface"
                get_list = True
            elif area == "arpTable":
                module_name = "ipstorage"
                list_name = "arpTable"
                get_list = True
            elif area == "routeTable":
                module_name = "ipstorage"
                list_name = "routeTable"
                get_list = True

            module_name = str_to_human(module_name)
            if get_list:  # maintaining the structure for future development if any
                list_name = str_to_human(list_name)
                ret_code, response = list_get(fos_user_name, fos_password, fos_ip_addr,
                                              module_name, list_name, fos_version,
                                              https, auth, vfid, result,
                                              ssh_hostkeymust, timeout)
                if ret_code != 0:
                    result[module_name + "_" + list_name + "_get"] = ret_code
                    exit_after_login(fos_ip_addr, https, auth, result, module, timeout)

                obj_list = response["Response"][str_to_yang(list_name)]
                if not isinstance(obj_list, list):
                    if obj_list is None:
                        obj_list = []
                    else:
                        obj_list = [obj_list]

                to_human_list(module_name, list_name, obj_list, result)
                facts[area] = obj_list

    result["ansible_facts"] = facts

    logout(fos_ip_addr, https, auth, result, timeout)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
