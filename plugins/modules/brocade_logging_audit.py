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

module: brocade_logging_audit
short_description: Brocade loggig audit Configuration
version_added: '2.7'
author: Broadcom BSN Ansible Team <Automation.BSN@broadcom.com>
description:
- Update logging audit configuration

options:
    credential:
        description:
        - login information including
          fos_ip_addr: ip address of the FOS switch
          fos_user_name: login name of FOS switch REST API
          fos_password: password of FOS switch REST API
          https: indicate if HTTPS or HTTP should be used to connect to FOS
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
    audit:
        description:
        - audit config data structure. All writable attributes supported
          by BSN REST API with - replaced with _.
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

  - name: initial audit configuration
    brocade_logging_audit:
      credential: "{{credential}}"
      vfid: -1
      audit:
        audit_enabled: True
        filter_class_list:
          filter_class:
          - "zone"
          - "security"
          - "configuration"
          - "firmware"
          - "fabric"
          - "ls"
          - "cli"
          - "maps"
        severity_level: "info"

"""


RETURN = """

msg:
    description: Success message
    returned: success
    type: str

"""


"""
Brocade Fibre Channel logging audit Configuration
"""


from ansible_collections.daniel_chung_broadcom.fos.plugins.module_utils.brocade_connection import login, logout, exit_after_login
from ansible_collections.daniel_chung_broadcom.fos.plugins.module_utils.brocade_yang import generate_diff
from ansible_collections.daniel_chung_broadcom.fos.plugins.module_utils.brocade_logging import audit_patch, audit_get, to_human_audit, to_fos_audit
from ansible.module_utils.basic import AnsibleModule


def main():
    """
    Main function
    """

    argument_spec = dict(
        credential=dict(required=True, type='dict'),
        vfid=dict(required=False, type='int'),
        throttle=dict(required=False, type='float'),
        audit=dict(required=True, type='dict'))

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
    vfid = input_params['vfid']
    audit = input_params['audit']
    result = {"changed": False}

    if vfid is None:
        vfid = 128

    ret_code, auth, fos_version = login(fos_ip_addr,
                           fos_user_name, fos_password,
                           https, throttle, result)
    if ret_code != 0:
        module.exit_json(**result)

    ret_code, response = audit_get(
        fos_ip_addr, https, auth, vfid, result)
    if ret_code != 0:
        exit_after_login(fos_ip_addr, https, auth, result, module)

    resp_audit = response["Response"]["audit"]

    to_human_audit(resp_audit)

    diff_attributes = generate_diff(result, resp_audit, audit)

    result["resp_audit"] = resp_audit
    result["audit"] = audit
    result["diff_attributes"] = diff_attributes

    if len(diff_attributes) > 0:
        ret_code = to_fos_audit(diff_attributes, result)
        if ret_code != 0:
            exit_after_login(fos_ip_addr, https, auth, result, module)

        if not module.check_mode:
            ret_code = audit_patch(
                fos_ip_addr, https,
                auth, vfid, result, diff_attributes)
            if ret_code != 0:
                exit_after_login(fos_ip_addr, https, auth, result, module)

        result["changed"] = True
    else:
        logout(fos_ip_addr, https, auth, result)
        module.exit_json(**result)

    logout(fos_ip_addr, https, auth, result)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
