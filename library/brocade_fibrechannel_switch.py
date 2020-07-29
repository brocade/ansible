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

module: brocade_fibrechannel_switch
short_description: Brocade Fibre Channel Switch Configuration
version_added: '2.7'
author: Broadcom BSN Ansible Team <Automation.BSN@broadcom.com>
description:
- Update Fibre Channel switch configuration.

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
    switch:
        description:
        - list of switch attributes. All writable attributes supported
          by BSN REST API with - replaced with _.
          Some examples are
          - user_friendly_name - switch name in string
          - fabric_user_friendly_name - fabric name in string
          - banner - login banner in string
          - domain_id - set the domain id of the switch
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

  - name: disable switch before setting insistent domain id mode and domain id set
    brocade_fibrechannel_switch:
      credential: "{{credential}}"
      vfid: -1
      switch:
        enabled_state: False

  - name: initial switch configuration
    brocade_fibrechannel_switch:
      credential: "{{credential}}"
      vfid: -1
      switch:
        user_friendly_name: "switch_name"
        fabric_user_friendly_name: "fabric_name"
        domain_id: 1
        banner: "AUTHORIZED USERS ONLY!"
        dynamic_load_sharing: "lossless-dls"
        domain_name: "yahoo.com"
        dns_servers:
          dns_server:
            - "8.8.8.8"
            - "8.8.4.4"

  - name: enable switch after setting insistent domain id mode
    brocade_fibrechannel_switch:
      credential: "{{credential}}"
      vfid: -1
      switch:
        enabled_state: True

"""


RETURN = """

msg:
    description: Success message
    returned: success
    type: str

"""


"""
Brocade Fibre Channel switch Configuration
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
        switch=dict(required=True, type='dict'))

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
    switch = input_params['switch']
    result = {"changed": False}

    list_helper(module, fos_ip_addr, fos_user_name, fos_password, https, ssh_hostkeymust, throttle, vfid, "brocade_fibrechannel_switch", "fibrechannel_switch", [switch], False, result, timeout)


if __name__ == '__main__':
    main()
