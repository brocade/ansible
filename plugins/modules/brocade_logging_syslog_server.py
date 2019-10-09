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
short_description: Brocade loggig syslog server Configuration
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
    syslog_servers:
        description:
        - list of syslog server config data structure
          All writable attributes supported
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
Brocade Fibre Channel syslog server Configuration
"""


from ansible.module_utils.brocade_connection import login, logout, exit_after_login
from ansible.module_utils.brocade_yang import generate_diff
from ansible.module_utils.brocade_logging import syslog_server_patch, syslog_server_post, syslog_server_delete, syslog_server_get, to_human_syslog_server, to_fos_syslog_server
from ansible.module_utils.basic import AnsibleModule


def main():
    """
    Main function
    """

    argument_spec = dict(
        credential=dict(required=True, type='dict'),
        vfid=dict(required=False, type='int'),
        throttle=dict(required=False, type='float'),
        syslog_servers=dict(required=True, type='list'))

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
    syslog_servers = input_params['syslog_servers']
    result = {"changed": False}

    if vfid is None:
        vfid = 128

    ret_code, auth, fos_version = login(fos_ip_addr,
                           fos_user_name, fos_password,
                           https, throttle, result)
    if ret_code != 0:
        module.exit_json(**result)

    ret_code, response = syslog_server_get(
        fos_ip_addr, https, auth, vfid, result)
    if ret_code != 0:
        exit_after_login(fos_ip_addr, https, auth, result, module)

    resp_ss = response["Response"]["syslog-server"]

    if isinstance(resp_ss, list):
        current_servers = resp_ss
    else:
        current_servers = [resp_ss]

    diff_servers = []
    for new_server in syslog_servers:
        for current_server in current_servers:
            if new_server["server"] == current_server["server"]:
                to_human_syslog_server(current_server)
                diff_attributes = generate_diff(result, current_server, new_server)
                if len(diff_attributes) > 0:
                    result["current_server"] = current_server
                    diff_attributes["server"] = new_server["server"]
                    ret_code = to_fos_syslog_server(diff_attributes, result)
                    result["retcode"] = ret_code
                    if ret_code != 0:
                        exit_after_login(fos_ip_addr, https, auth, result, module)

                    diff_servers.append(diff_attributes)

    add_servers = []
    for new_server in syslog_servers:
        found = False
        for current_server in current_servers:
            if new_server["server"] == current_server["server"]:
                found = True
        if not found:
            new_yang_server = {}
            secured = ("secured_mode" in new_server and new_serer["secured_mode"] == True)
            if secured:
                for k, v in new_server.items():
                    new_yang_server[k] = v
            else:
                for k, v in new_server.items():
                    if k == "server":
                        new_yang_server[k] = v
            ret_code = to_fos_syslog_server(new_yang_server, result)
            result["retcode"] = ret_code
            if ret_code != 0:
                exit_after_login(fos_ip_addr, https, auth, result, module)

            add_servers.append(new_yang_server)

    delete_servers = []
    for current_server in current_servers:
        found = False
        for new_server in syslog_servers:
            if new_server["server"] == current_server["server"]:
                found = True
        if not found:
            delete_server = {}
            delete_server["server"] = current_server["server"]
            delete_servers.append(delete_server)

    result["resp_ss"] = resp_ss
    result["syslog_servers"] = syslog_servers
    result["diff_servers"] = diff_servers
    result["add_servers"] = add_servers
    result["delete_servers"] = delete_servers

    if len(diff_servers) > 0:
        if not module.check_mode:
            ret_code = syslog_server_patch(
                fos_ip_addr, https,
                auth, vfid, result, diff_servers)
            if ret_code != 0:
                exit_after_login(fos_ip_addr, https, auth, result, module)

        result["changed"] = True

    if len(add_servers) > 0:
        if not module.check_mode:
            ret_code = syslog_server_post(
                fos_ip_addr, https,
                auth, vfid, result, add_servers)
            if ret_code != 0:
                exit_after_login(fos_ip_addr, https, auth, result, module)

        result["changed"] = True

    if len(delete_servers) > 0:
        if not module.check_mode:
            ret_code = syslog_server_delete(
                fos_ip_addr, https,
                auth, vfid, result, delete_servers)
            if ret_code != 0:
                exit_after_login(fos_ip_addr, https, auth, result, module)

        result["changed"] = True

    logout(fos_ip_addr, https, auth, result)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
