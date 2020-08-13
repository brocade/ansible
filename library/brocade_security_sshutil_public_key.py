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

module: brocade_security_ssh_public_key
short_description: Brocade security ssh public key delete only
version_added: '2.7'
author: Broadcom BSN Ansible Team <Automation.BSN@broadcom.com>
description:
- Used to delete public key


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
    delete_sshutil_public_key:
        description:
        - list of user names to delete the keys
        required: false

'''


EXAMPLES = """

  gather_facts: False

  vars:
    credential:
      fos_ip_addr: "{{fos_ip_addr}}"
      fos_user_name: admin
      fos_password: xxx
      https: False

  tasks:

  - name: delete public key for admin
    brocade_security_user_config:
      credential: "{{credential}}"
      vfid: -1
      delete_sshutil_public_key:
        - user-name: "admin"

"""


RETURN = """

msg:
    description: Success message
    returned: success
    type: str

"""


"""
Brocade Fibre Channel user config Configuration
"""


from ansible.module_utils.brocade_objects import list_helper, list_delete_helper
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
        delete_sshutil_public_key=dict(required=False, type='list'))

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
    delete_sshutil_public_key = input_params['delete_sshutil_public_key']
    result = {"changed": False}

    # if delete sshutil_public_key is not None, then we make sure
    # the user config is not present.
    if delete_sshutil_public_key != None:
        return list_delete_helper(module, fos_ip_addr, fos_user_name, fos_password, https, ssh_hostkeymust, throttle, vfid, "brocade_security", "sshutil_public_key", delete_sshutil_public_key, True, result, timeout)


if __name__ == '__main__':
    main()
