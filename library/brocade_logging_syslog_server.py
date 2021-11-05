#!/usr/bin/env python3

# Copyright 2019 Broadcom. All rights reserved.
# The term 'Broadcom' refers to Broadcom Inc. and/or its subsidiaries.
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import (absolute_import, division, print_function)
__metaclass__ = type


DOCUMENTATION = '''

module: brocade_logging_syslog
short_description: Brocade Fibre Channel loggig syslog server configuration
version_added: '2.7'
author: Broadcom BSN Ansible Team <Automation.BSN@broadcom.com>
description:
- Update Fibre Channel logging audit configuration

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
    all_entries:
        description:
        - Boolean to indicate if the entries specified are full
          list of objects or not. By default, all_entries are
          thought to be true if not specified. If all_entries
          is set to true, the entries is used to calculate the change
          of existing entryies, addition, and deletion. If
          all_entries is set to false, the entries is used to
          calculate the change of existing entries and addition
          of entries only. i.e. the module will not attempt to
          delete objects that do not show up in the entries.
        required: false
        type: bool
    syslog_servers:
        description:
        - List of syslog server config data structure.
          All writable attributes supported
          by BSN REST API with - replaced with _.
        required: true
        type: list 
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

  - name: initial syslog configuration
    brocade_logging_syslog_server:
      credential: "{{credential}}"
      vfid: -1
      syslog_servers:
        - port: 514
          secure_mode: False
          server: "10.155.2.151"

"""


RETURN = """

msg:
    description: Success message
    returned: success
    type: str

"""


"""
Brocade Fibre Channel syslog server configuration
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
        syslog_servers=dict(required=True, type='list'),
        all_entries=dict(required=False, type='bool'))

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
    syslog_servers = input_params['syslog_servers']
    result = {"changed": False}
    all_entries = input_params['all_entries']

    if all_entries == None:
        all_entries = False

    list_helper(module, fos_ip_addr, fos_user_name, fos_password, https, True, throttle, vfid, "brocade_logging", "syslog_server", syslog_servers, all_entries, result, timeout)


if __name__ == '__main__':
    main()
