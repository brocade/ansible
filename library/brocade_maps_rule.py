#!/usr/bin/python

# Copyright 2019-2025 Broadcom. All rights reserved.
# The term 'Broadcom' refers to Broadcom Inc. and/or its subsidiaries.
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import (absolute_import, division, print_function)
__metaclass__ = type


ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'certified'}


DOCUMENTATION = '''

module: brocade_maps_rule
short_description: Brocade Fibre Channel MAPS rule configuration
version_added: '2.7'
author: Broadcom BSN Ansible Team <Automation.BSN@broadcom.com>
description:
- Update Fibre Channel MAPS rule

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
    rules:
        description:
        - list of rules to be updated. All writable attributes supported
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


  - name: configure maps rules
    brocade_maps_rule:
    credential: "{{credential}}"
    vfid: -1
    rules:
      - name: my_rule1
        actions:
          action:
            - "raslog"
        event_severity: null
        group_name: "ALL_E_PORTS"
        is_rule_on_rule: False
        logical_operator: "g"
        monitoring_system: "C3TXTO"
        quiet_time: 0
        threshold_value: 1
        time_base: "Min"

"""


RETURN = """

msg:
    description: Success message
    returned: success
    type: str

"""


"""
Brocade Fibre Channel MAPS rule configuration
"""


from ansible.module_utils.brocade_objects import list_helper
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
        all_entries=dict(required=False, type='bool'),
        rules=dict(required=True, type='list'))

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
    all_entries = input_params['all_entries']
    rules = input_params['rules']
    result = {"changed": False}

    list_helper(module, fos_ip_addr, fos_user_name, fos_password, https, True, throttle, vfid, "brocade_maps", "rule", rules, all_entries, result, timeout)


if __name__ == '__main__':
    main()
