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

module: brocade_zoning_cfg
short_description: Brocade Zoning Cfgs
version_added: '2.7'
author: Broadcom BSN Ansible Team <Automation.BSN@broadcom.com>
description:
- Create, detroy, or update Cfgs. The whole of cfgs and
  cfgs_to_delete are applied to FOS within a single login session
  to termininate after the completion. If no active cfg is found,
  cfgsave is executed before the completion of the session. If an
  active cfg is found, cfgenable of the existing cfg is executed
  to apply any potential changes before the completion of the session.

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
    cfgs:
        description:
        - List of cfgs to be created or modified. If an cfg does
          not exist in the current Zone Database, the cfg will be
          created with the members specified. If an cfg already
          exists in the current Zone Database, the cfg is updated to
          reflect to members specificed. In other word, new members
          will be added and removed members will be removed. cfgs and
          cfgs_to_delete are mutually exclusive.
        required: false
    members_add_only:
        description:
        - If set to True, new members will be added and old members
          not specified also remain
    members_remove_only:
        description:
        - If set to True, members specified are removed
        required: false
    cfgs_to_delete:
        description:
        - List of cfgs to be deleted. cfgs and cfgs_to_delete are
          mutually exclusive.
        required: false
    active_cfg:
        description:
        - cfg to be enabled (cfg_enable) at the end. If no cfg is
          specified, cfgs are saved (cfg_save).
        required: false

'''


EXAMPLES = """

  gather_facts: False

  vars:
    credential:
      fos_ip_addr: "{{fos_ip_addr}}"
      fos_user_name: admin
      fos_password: fibranne
      https: False
    cfgs:
      - name: newcfg1
        members:
          - NewZoneName
          - NewZoneName2
      - name: newcfg2
        members:
          - NewZoneName
          - NewZoneName2
      - name: newcfg3
        members:
          - NewZoneName
          - NewZoneName2
    cfgs_to_delete:
      - name: newcfg2
      - name: newcfg3

  tasks:

  - name: Create cfgs
    brocade_zoning_cfg:
      credential: "{{credential}}"
      vfid: -1
      cfgs: "{{cfgs}}"
#      cfgs_to_delete: "{{cfgs_to_delete}}"
      active_cfg: newcfg2

"""


RETURN = """

msg:
    description: Success message
    returned: success
    type: str

"""

"""
Brocade Zoning Cfgs
"""


from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.brocade_connection import login, logout, exit_after_login
from ansible.module_utils.brocade_zoning import zoning_common, cfg_post, cfg_delete, cfg_get, cfg_process_diff, cfg_process_diff_to_delete


def main():
    """
    Main function
    """

    argument_spec = dict(
        credential=dict(required=True, type='dict', no_log=True),
        vfid=dict(required=False, type='int'),
        throttle=dict(required=False, type='float'),
        timeout=dict(required=False, type='float'),
        cfgs=dict(required=False, type='list'),
        members_add_only=dict(required=False, type='bool'),
        members_remove_only=dict(required=False, type='bool'),
        cfgs_to_delete=dict(required=False, type='list'),
        active_cfg=dict(required=False, type='str'))

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
    cfgs = input_params['cfgs']
    members_add_only = input_params['members_add_only']
    members_remove_only = input_params['members_remove_only']
    cfgs_to_delete = input_params['cfgs_to_delete']
    active_cfg = input_params['active_cfg']
    result = {"changed": False}

    if vfid is None:
        vfid = 128

    ret_code, auth, fos_version = login(fos_ip_addr,
                           fos_user_name, fos_password,
                           https, throttle, result, timeout)
    if ret_code != 0:
        module.exit_json(**result)

    zoning_common(fos_ip_addr, https, auth, vfid, result, module, cfgs,
                  members_add_only, members_remove_only, cfgs_to_delete, "cfg",
                  cfg_process_diff, cfg_process_diff_to_delete,
                  cfg_get, cfg_post, cfg_delete, active_cfg, timeout)

    ret_code = logout(fos_ip_addr, https, auth, result, timeout)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
