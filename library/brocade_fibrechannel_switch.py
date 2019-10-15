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
- Update Fibre Channel switch configuration

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


from ansible.module_utils.brocade_connection import login, logout, exit_after_login
from ansible.module_utils.brocade_yang import generate_diff
from ansible.module_utils.brocade_fibrechannel_switch import fc_switch_patch, fc_switch_get, to_human_switch, to_fos_switch
from ansible.module_utils.basic import AnsibleModule


def main():
    """
    Main function
    """

    argument_spec = dict(
        credential=dict(required=True, type='dict'),
        vfid=dict(required=False, type='int'),
        throttle=dict(required=False, type='float'),
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
    throttle = input_params['throttle']
    vfid = input_params['vfid']
    switch = input_params['switch']
    result = {"changed": False}

    if vfid is None:
        vfid = 128

    ret_code, auth, fos_version = login(fos_ip_addr,
                           fos_user_name, fos_password,
                           https, throttle, result)
    if ret_code != 0:
        module.exit_json(**result)

    ret_code, response = fc_switch_get(fos_user_name, fos_password, 
        fos_ip_addr, fos_version, https, auth, vfid, result)
    if ret_code != 0:
        exit_after_login(fos_ip_addr, https, auth, result, module)

    resp_switch = response["Response"]["fibrechannel-switch"]

    to_human_switch(resp_switch)
   
    if "dns_servers" in resp_switch:
        if resp_switch["dns_servers"] is not None and "dns_server" in resp_switch["dns_servers"]:
            if not isinstance(resp_switch["dns_servers"]["dns_server"], list):
                new_list = []
                new_list.append(resp_switch["dns_servers"]["dns_server"])
                resp_switch["dns_servers"]["dns_server"] = new_list

    diff_attributes = generate_diff(result, resp_switch, switch)

    result["diff_attributes"] = diff_attributes
    result["resp_switch"] = resp_switch
    result["switch"] = switch

    if len(diff_attributes) > 0:
        # let's add name key to it
        diff_attributes["name"] = resp_switch["name"]
        ret_code = to_fos_switch(diff_attributes, result)
        if ret_code != 0:
            exit_after_login(fos_ip_addr, https, auth, result, module)

        if not module.check_mode:
            ret_code = fc_switch_patch(fos_user_name, fos_password,
                                       fos_ip_addr, fos_version, https,
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
