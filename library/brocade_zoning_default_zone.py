#!/usr/bin/python

# Copyright 2019-2025 Broadcom. All rights reserved.
# The term 'Broadcom' refers to Broadcom Inc. and/or its subsidiaries.
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import (absolute_import, division, print_function)
__metaclass__ = type


DOCUMENTATION = '''

module: brocade_zoning_default_zone
short_description: Brocade Fibre Channel zoning default zone configuration
version_added: '2.7'
author: Broadcom BSN Ansible Team <Automation.BSN@broadcom.com>
description:
- Update Fibre Channel zoning's default zone configuration

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
    default_zone_access:
        description:
        - Default zone access mode. "allaccess" to indicate all access
          "noaccess" to indicate no access.
        required: false
        type: str

'''


EXAMPLES = """

  gather_facts: False

  vars:
    credential:
      fos_ip_addr: "{{fos_ip_addr}}"
      fos_user_name: admin
      fos_password: password
      https: False

  tasks:

  - name: Default zoning
    brocade_zoning_default_zone:
      credential: "{{credential}}"
      vfid: -1
      default_zone_access: allaccess

"""


RETURN = """

msg:
    description: Success message
    returned: success
    type: str

"""


"""
Brocade Fibre Channel default zone Configuration
"""


from ansible.module_utils.brocade_connection import login, logout, exit_after_login
from ansible.module_utils.brocade_zoning import effective_get, effective_patch, cfg_save, cfg_abort, to_human_zoning, to_fos_zoning
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
        default_zone_access=dict(required=False, type='str'))

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
    default_zone_access = input_params['default_zone_access']
    result = {"changed": False}

    if vfid is None:
        vfid = 128

    ret_code, auth, fos_version = login(fos_ip_addr,
                           fos_user_name, fos_password,
                           https, throttle, result, timeout)
    if ret_code != 0:
        module.exit_json(**result)

    ret_code, response = effective_get(fos_ip_addr, https, fos_version, auth, vfid, result, timeout)
    if ret_code != 0:
        exit_after_login(fos_ip_addr, https, auth, result, module, timeout)

    resp_effective = response["Response"]["effective-configuration"]

    to_human_zoning(resp_effective)

    diff_attributes = {}
    if (default_zone_access is not None and
        default_zone_access != resp_effective["default_zone_access"]):
        diff_attributes["default_zone_access"] = default_zone_access

    if len(diff_attributes) > 0:
        ret_code = to_fos_zoning(diff_attributes, result)
        if ret_code != 0:
            exit_after_login(fos_ip_addr, https, auth, result, module, timeout)

        if not module.check_mode:
            ret_code = effective_patch(fos_ip_addr, https, fos_version,
                                       auth, vfid, result, diff_attributes, timeout)
            if ret_code != 0:
                exit_after_login(fos_ip_addr, https, auth, result, module, timeout)

            checksum = resp_effective["checksum"]
            ret_code = cfg_save(fos_ip_addr, https, fos_version, auth, vfid,
                                result, checksum, timeout)
            if ret_code != 0:
                ret_code = cfg_abort(fos_ip_addr, https, fos_version, auth, vfid, result, timeout)
                exit_after_login(fos_ip_addr, https, auth, result, module, timeout)

        result["changed"] = True
    else:
        logout(fos_ip_addr, https, auth, result, timeout)
        module.exit_json(**result)

    logout(fos_ip_addr, https, auth, result, timeout)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
