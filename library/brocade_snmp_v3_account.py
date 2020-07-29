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

module: brocade_snmp_v3_account
short_description: Brocade Fibre Channel SNMP v3 account configuration
version_added: '2.7'
author: Broadcom BSN Ansible Team <Automation.BSN@broadcom.com>
description:
- Update Fibre Channel SNMP v3 account

options:

    credential:
        description:
        - login information including
          fos_ip_addr - ip address of the FOS switch
          fos_user_name - login name of FOS switch REST API
          fos_password - password of FOS switch REST API
          https - True for HTTPS, self for self-signed HTTPS, or False for HTTP
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
    v3_accounts:
        description:
        - list of v3 accounts to be updated. All writable attributes supported
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


  - name: snmp v3 accounts
    brocade_snmp_v3_account:
    credential: "{{credential}}"
    vfid: -1
    v3_accounts:
      - index: 1
        authentication_protocol: "md5"
        manager_engine_id: "00:00:00:00:00:00:00:00:00"
        privacy_protocol: "aes128"
        user_name: "asc-test"
      - index: 2
        authentication_protocol: "sha"
        manager_engine_id: "00:00:00:00:00:00:00:00:00"
        privacy_protocol: "des"
        user_name: "snmpadmin2"

"""


RETURN = """

msg:
    description: Success message
    returned: success
    type: str

"""


"""
Brocade Fibre Channel SNMP v3 account configuration
"""


from ansible.module_utils.brocade_objects import list_helper
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
        v3_accounts=dict(required=True, type='list'))

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
    v3_accounts = input_params['v3_accounts']
    result = {"changed": False}

    list_helper(module, fos_ip_addr, fos_user_name, fos_password, https, True, throttle, vfid, "brocade_snmp", "v3_account", v3_accounts, False, result, timeout)


if __name__ == '__main__':
    main()
