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

module: brocade_zoning_zone
short_description: Brocade Zoning Zones
version_added: '2.7'
author: Broadcom BSN Ansible Team <Automation.BSN@broadcom.com>
description:
- Create, detroy, or update Zones. The whole of zones and
  zones_to_delete are applied to FOS within a single login session
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
    zones:
        description:
        - List of zones to be created or modified. If a zone does
          not exist in the current Zone Database, the zone will be
          created with the members specified. If a zone already
          exist in the current Zone Database, the zone is updated to
          reflect to members specificed. In other word, new members
          will be added and removed members will be removed.
          Peerzones are automatically created only if optional principal
          members are specified. zones are zones_to_delete are mutually
          exclusive.
        required: true
    members_add_only:
        description:
        - If set to True, new members will be added and old members
          not specified also remain
    members_remove_only:
        description:
        - If set to True, members specified are removed
        required: false
    zones_to_delete:
        description:
        - List of zones to be deleted. zones are zones_to_delete are mutually
          exclusive.
        required: true

'''


EXAMPLES = """

  gather_facts: False

  vars:
    credential:
      fos_ip_addr: "{{fos_ip_addr}}"
      fos_user_name: admin
      fos_password: fibranne
      https: False
    zones:
      - name: NewZoneName
        members:
          - Host1
          - Target1
          - Target2
      - name: NewZoneName2
        members:
          - Host1
          - Target2
      - name: NewZoneNameP
        members:
          - 11:22:33:44:55:66:77:88
        principal_members:
          - 22:22:33:44:55:66:77:88
    zones_to_delete:
      - name: NewZoneNameP
      - name: NewZoneName2

  tasks:

  - name: Create zones
    brocade_zoning_zone:
      credential: "{{credential}}"
      vfid: -1
      zones: "{{zones}}"
#      zones_to_delete: "{{zones_to_delete}}"

"""


RETURN = """

msg:
    description: Success message
    returned: success
    type: str

"""


"""
Brocade Zoning Zones
"""


from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.brocade_connection import login, logout, exit_after_login
from ansible.module_utils.brocade_zoning import zoning_common, zone_post, zone_delete, zone_get, zone_process_diff, zone_process_diff_to_delete


def main():
    """
    Main function
    """

    argument_spec = dict(
        credential=dict(required=True, type='dict', no_log=True),
        vfid=dict(required=False, type='int'),
        throttle=dict(required=False, type='float'),
        timeout=dict(required=False, type='float'),
        zones=dict(required=False, type='list'),
        members_add_only=dict(required=False, type='bool'),
        members_remove_only=dict(required=False, type='bool'),
        zones_to_delete=dict(required=False, type='list'))

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
    zones = input_params['zones']
    members_add_only = input_params['members_add_only']
    members_remove_only = input_params['members_remove_only']
    zones_to_delete = input_params['zones_to_delete']
    result = {"changed": False}

    if vfid is None:
        vfid = 128

    ret_code, auth, fos_version = login(fos_ip_addr,
                           fos_user_name, fos_password,
                           https, throttle, result, timeout)
    if ret_code != 0:
        module.exit_json(**result)

    zoning_common(fos_ip_addr, https, auth, vfid, result, module, zones,
                  members_add_only, members_remove_only, zones_to_delete, "zone",
                  zone_process_diff, zone_process_diff_to_delete, zone_get,
                  zone_post, zone_delete, None, timeout)

    ret_code = logout(fos_ip_addr, https, auth, result, timeout)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
