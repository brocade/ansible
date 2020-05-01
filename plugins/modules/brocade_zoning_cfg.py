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
          fos_ip_addr: ip address of the FOS switch
          fos_user_name: login name of FOS switch REST API
          fos_password: password of FOS switch REST API
          https: True for HTTPS, self for self-signed HTTPS, or False for HTTP
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
from ansible_collections.daniel_chung_broadcom.fos.plugins.module_utils.brocade_connection import login, logout, exit_after_login
from ansible_collections.daniel_chung_broadcom.fos.plugins.module_utils.brocade_zoning import zoning_common, cfg_post, cfg_delete, cfg_get, process_member_diff


def cfg_process_diff(result, cfgs, c_cfgs):
    """
    return the diff from expected cfgs vs. current cfgs

    :param cfgs: list of expected cfgs
    :type cfgs: list
    :param c_cfgs: list of current cfgs
    :type c_cfgs: list
    :return: indicate if diff or the same
    :rtype: bool
    :return: list of cfgs with to be added members
    :rtype: list
    :return: list of cfgs with to be removed members
    :rtype: list
    """
    post_cfgs = []
    remove_cfgs = []
    for cfg in cfgs:
        found_in_c = False
        for c_cfg in c_cfgs:
            if cfg["name"] == c_cfg["cfg-name"]:
                found_in_c = True
                added_members, removed_members = process_member_diff(
                    result, cfg["members"], c_cfg["member-zone"]["zone-name"])

                if len(added_members) > 0:
                    post_cfg = {}
                    post_cfg["name"] = cfg["name"]
                    post_cfg["members"] = added_members
                    post_cfgs.append(post_cfg)
                if len(removed_members) > 0:
                    remove_cfg = {}
                    remove_cfg["name"] = cfg["name"]
                    remove_cfg["members"] = removed_members
                    remove_cfgs.append(remove_cfg)
                continue
        if not found_in_c:
            post_cfgs.append(cfg)

    return 0, post_cfgs, remove_cfgs


def cfg_process_diff_to_delete(result, cfgs, c_cfgs):
    """
    return the diff from to delete cfgs vs. current cfgs

    :param cfgs: list of expected cfgs
    :type cfgs: list
    :param c_cfgs: list of current cfgs
    :type c_cfgs: list
    :return: indicate if diff or the same
    :rtype: bool
    :return: list of cfgs to delete
    :rtype: list
    :return: list of cfgs with to be removed members
    :rtype: list
    """
    delete_cfgs = []
    for cfg in cfgs:
        found_in_c = False
        for c_cfg in c_cfgs:
            if cfg["name"] == c_cfg["cfg-name"]:
                found_in_c = True
                break
        if found_in_c:
            delete_cfgs.append(cfg)

    return 0, delete_cfgs


def main():
    """
    Main function
    """

    argument_spec = dict(
        credential=dict(required=True, type='dict'),
        vfid=dict(required=False, type='int'),
        throttle=dict(required=False, type='float'),
        cfgs=dict(required=False, type='list'),
        members_add_only=dict(required=False, type='bool'),
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
    vfid = input_params['vfid']
    cfgs = input_params['cfgs']
    members_add_only = input_params['members_add_only']
    cfgs_to_delete = input_params['cfgs_to_delete']
    active_cfg = input_params['active_cfg']
    result = {"changed": False}

    if vfid is None:
        vfid = 128

    ret_code, auth, fos_version = login(fos_ip_addr,
                           fos_user_name, fos_password,
                           https, throttle, result)
    if ret_code != 0:
        module.exit_json(**result)

    zoning_common(fos_ip_addr, https, auth, vfid, result, module, cfgs,
                  members_add_only, cfgs_to_delete, "cfg",
                  cfg_process_diff, cfg_process_diff_to_delete,
                  cfg_get, cfg_post, cfg_delete, active_cfg)

    ret_code = logout(fos_ip_addr, https, auth, result)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
