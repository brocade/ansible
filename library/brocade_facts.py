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

module: brocade_facts
short_description: Brocade facts gathering
version_added: '2.6'
author: Broadcom BSN Ansible Team <Automation.BSN@broadcom.com>
description:
- Gather FOS facts.

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
    gather_subset:
        description:
        - list of areas to be gathered. If this option is missing,
          all areas' facts will be gathered. Same behavior applies
          if "all" is listed as part of gather_subset. Valid entries are:
            brocade_zoning
            brocade_interface_fibrechannel
            brocade_chassis_chassis
            brocade_fibrechannel_configuration_fabric
            brocade_fibrechannel_configuration_port_configuration
            brocade_fibrechannel_switch
            brocade_fibrechannel_trunk_trunk
            brocade_fibrechannel_trunk_performance
            brocade_fibrechannel_trunk_trunk_area
            brocade_time_clock_server
            brocade_time_time_zone
            brocade_logging_syslog_server
            brocade_logging_audit
            brocade_media_media_rdp
            brocade_snmp_system
            brocade_security_ipfilter_rule
            brocade_security_ipfilter_policy
            brocade_security_user_config
            brocade_security_password_cfg
            brocade_security_security_certificate
        required: true

'''


EXAMPLES = """

  var:
    credential:
      fos_ip_addr: "{{fos_ip_addr}}"
      fos_user_name: admin
      fos_password: fibranne
      https: False

  tasks:

  - name: gather facts
    brocade_facts:
      credential: "{{credential}}"
      vfid: -1
      gather_subset:
        - brocade_zoning
        - brocade_interface_fibrechannel
        - brocade_chassis_chassis
        - brocade_fibrechannel_configuration_fabric
        - brocade_fibrechannel_configuration_port_configuration
        - brocade_fibrechannel_switch
        - brocade_time_clock_server
        - brocade_time_time_zone
        - brocade_logging_syslog_server
        - brocade_logging_audit
        - brocade_snmp_system
        - brocade_security_ipfilter_rule
        - brocade_security_ipfilter_policy
        - brocade_security_user_config

  - name: print ansible_facts gathered
    debug:
      var: ansible_facts

"""


RETURN = """

msg:
    description: Success message
    returned: success
    type: str

"""


"""
Brocade Fibre Channel Port Configuration
"""


from ansible.module_utils.brocade_connection import login, logout, exit_after_login
from ansible.module_utils.brocade_zoning import defined_get, effective_get, to_human_zoning
from ansible.module_utils.brocade_objects import singleton_get, list_get, to_human_singleton, to_human_list
from ansible.module_utils.brocade_yang import str_to_yang
from ansible.module_utils.basic import AnsibleModule


valid_areas = [
    "brocade_access_gateway_port_group",
    "brocade_access_gateway_n_port_map",
    "brocade_access_gateway_f_port_list",
    "brocade_access_gateway_device_list",
    "brocade_access_gateway_policy",
    "brocade_access_gateway_n_port_settings",
    "brocade_zoning",
    "brocade_interface_fibrechannel",
    "brocade_chassis_chassis",
    "brocade_fabric_fabric_switch",
    "brocade_fibrechannel_configuration_fabric",
    "brocade_fibrechannel_configuration_port_configuration",
    "brocade_fibrechannel_switch",
    "brocade_fibrechannel_trunk_trunk",
    "brocade_fibrechannel_trunk_performance",
    "brocade_fibrechannel_trunk_trunk_area",
    "brocade_time_clock_server",
    "brocade_time_time_zone",
    "brocade_logging_syslog_server",
    "brocade_logging_audit",
    "brocade_media_media_rdp",
    "brocade_snmp_system",
    "brocade_security_ipfilter_rule",
    "brocade_security_ipfilter_policy",
    "brocade_security_user_config",
    "brocade_security_password_cfg",
    "brocade_security_security_certificate",
    "brocade_security_sshutil_public_key",
    ]


def main():
    """
    Main function
    """

    argument_spec = dict(
        credential=dict(required=True, type='dict', no_log=True),
        vfid=dict(required=False, type='int'),
        throttle=dict(required=False, type='float'),
        timeout=dict(required=False, type='float'),
        gather_subset=dict(required=True, type='list'))

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=False
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
    gather_subset = input_params['gather_subset']
    result = {"changed": False}

    if vfid is None:
        vfid = 128

    ret_code, auth, fos_version = login(fos_ip_addr,
                           fos_user_name, fos_password,
                           https, throttle, result, timeout)
    if ret_code != 0:
        module.exit_json(**result)

    facts = {}

    facts['ssh_hostkeymust'] = ssh_hostkeymust

    if gather_subset is not None:
        for subset in gather_subset:
            if subset != "all" and subset not in valid_areas:
                result["failed"] = True
                result["msg"] = "Request for unknown module and object " + subset
                logout(fos_ip_addr, https, auth, result, timeout)
                module.exit_json(**result)

    for area in valid_areas:
        if (gather_subset is None or area in gather_subset or "all" in gather_subset):
            get_list = False
            get_singleton = False

            if area == "brocade_access_gateway_port_group":
                module_name = "brocade_access_gateway"
                list_name = "port_group"
                get_list = True
            elif area == "brocade_access_gateway_n_port_map":
                module_name = "brocade_access_gateway"
                list_name = "n_port_map"
                get_list = True
            elif area == "brocade_access_gateway_f_port_list":
                module_name = "brocade_access_gateway"
                list_name = "f_port_list"
                get_list = True
            elif area == "brocade_access_gateway_device_list":
                module_name = "brocade_access_gateway"
                list_name = "device_list"
                get_list = True
            elif area == "brocade_access_gateway_policy":
                module_name = "brocade_access_gateway"
                obj_name = "policy"
                get_singleton = True
            elif area == "brocade_access_gateway_n_port_settings":
                module_name = "brocade_access_gateway"
                obj_name = "n_port_settings"
                get_singleton = True
            elif area == "brocade_interface_fibrechannel":
                module_name = "brocade_interface"
                list_name = "fibrechannel"
                get_list = True
            elif area == "brocade_fibrechannel_switch":
                module_name = "brocade_fibrechannel_switch"
                list_name = "fibrechannel_switch"
                get_list = True
            elif area == "brocade_logging_syslog_server":
                module_name = "brocade_logging"
                list_name = "syslog_server"
                get_list = True
            elif area == "brocade_security_ipfilter_rule":
                module_name = "brocade_security"
                list_name = "ipfilter_rule"
                get_list = True
            elif area == "brocade_security_ipfilter_policy":
                module_name = "brocade_security"
                list_name = "ipfilter_policy"
                get_list = True
            elif area == "brocade_security_user_config":
                module_name = "brocade_security"
                list_name = "user_config"
                get_list = True
            elif area == "brocade_security_security_certificate":
                module_name = "brocade_security"
                list_name = "security_certificate"
                get_list = True
            elif area == "brocade_security_sshutil_public_key":
                module_name = "brocade_security"
                list_name = "sshutil_public_key"
                get_list = True
            elif area == "brocade_media_media_rdp":
                module_name = "brocade_media"
                list_name = "media_rdp"
                get_list = True
            elif area == "brocade_fibrechannel_trunk_trunk":
                module_name = "brocade_fibrechannel_trunk"
                list_name = "trunk"
                get_list = True
            elif area == "brocade_fibrechannel_trunk_performance":
                module_name = "brocade_fibrechannel_trunk"
                list_name = "performance"
                get_list = True
            elif area == "brocade_fibrechannel_trunk_trunk_area":
                module_name = "brocade_fibrechannel_trunk"
                list_name = "trunk_area"
                get_list = True
            elif area == "brocade_fabric_fabric_switch":
                module_name = "brocade_fabric"
                list_name = "fabric_switch"
                get_list = True
            elif area == "brocade_security_password_cfg":
                module_name = "brocade_security"
                obj_name = "password_cfg"
                get_singleton = True
            elif area == "brocade_chassis_chassis":
                module_name = "brocade_chassis"
                obj_name = "chassis"
                get_singleton = True
            elif area == "brocade_fibrechannel_configuration_fabric":
                module_name = "brocade_fibrechannel_configuration"
                obj_name = "fabric"
                get_singleton = True
            elif area == "brocade_fibrechannel_configuration_port_configuration":
                module_name = "brocade_fibrechannel_configuration"
                obj_name = "port_configuration"
                get_singleton = True
            elif area == "brocade_time_clock_server":
                module_name = "brocade_time"
                obj_name = "clock_server"
                get_singleton = True
            elif area == "brocade_time_time_zone":
                module_name = "brocade_time"
                obj_name = "time_zone"
                get_singleton = True
            elif area == "brocade_logging_audit":
                module_name = "brocade_logging"
                obj_name = "audit"
                get_singleton = True
            elif area == "brocade_snmp_system":
                module_name = "brocade_snmp"
                obj_name = "system"
                get_singleton = True

            if get_singleton:
                ret_code, response = singleton_get(fos_user_name, fos_password, fos_ip_addr,
                                                   module_name, obj_name, fos_version,
                                                   https, auth, vfid, result,
                                                   ssh_hostkeymust, timeout)
                if ret_code != 0:
                    result[module_name + "_" + obj_name + "_get"] = ret_code
                    exit_after_login(fos_ip_addr, https, auth, result, module, timeout)

                obj = response["Response"][str_to_yang(obj_name)]

                to_human_singleton(module_name, obj_name, obj)

                facts[area] = obj
            elif get_list:
                ret_code, response = list_get(fos_user_name, fos_password, fos_ip_addr,
                                              module_name, list_name, fos_version,
                                              https, auth, vfid, result,
                                              ssh_hostkeymust, timeout)
                if ret_code != 0:
                    result[module_name + "_" + list_name + "_get"] = ret_code
                    exit_after_login(fos_ip_addr, https, auth, result, module, timeout)

                obj_list = response["Response"][str_to_yang(list_name)]
                if not isinstance(obj_list, list):
                    if obj_list is None:
                        obj_list = []
                    else:
                        obj_list = [obj_list]

                to_human_list(module_name, list_name, obj_list, result)
                facts[area] = obj_list
            elif area == "brocade_zoning":
                ret_code, response = defined_get(
                    fos_ip_addr, https, auth, vfid, result, timeout)
                if ret_code != 0:
                    exit_after_login(fos_ip_addr, https, auth, result, module, timeout)

                zoning = {}
                zoning["defined-configuration"] = (
                    response["Response"]["defined-configuration"]
                )

                ret_code, response = effective_get(
                    fos_ip_addr, https, auth, vfid, result, timeout)
                if ret_code != 0:
                    exit_after_login(fos_ip_addr, https, auth, result, module, timeout)

                zoning["effective-configuration"] = (
                    response["Response"]["effective-configuration"]
                )

                to_human_zoning(zoning["effective-configuration"])

                facts[area] = zoning

    result["ansible_facts"] = facts

    logout(fos_ip_addr, https, auth, result, timeout)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
