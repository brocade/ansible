#!/usr/bin/python

# Copyright 2019-2025 Broadcom. All rights reserved.
# The term 'Broadcom' refers to Broadcom Inc. and/or its subsidiaries.
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import (absolute_import, division, print_function)
__metaclass__ = type


DOCUMENTATION = '''

module: brocade_facts
short_description: Brocade Fibre Channel facts gathering
version_added: '2.6'
author: Broadcom BSN Ansible Team <Automation.BSN@broadcom.com>
description:
- Gather FOS facts

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
    gather_subset:
        description:
        - List of areas to be gathered. If this option is missing,
          all areas' facts will be gathered. Same behavior applies
          if "all" is listed as part of gather_subset.
        choices:
            - all
            - brocade_access_gateway_port_group
            - brocade_access_gateway_n_port_map
            - brocade_access_gateway_f_port_list
            - brocade_access_gateway_device_list
            - brocade_access_gateway_policy
            - brocade_access_gateway_n_port_settings
            - brocade_zoning
            - brocade_interface_fibrechannel
            - brocade_chassis_chassis
            - brocade_fibrechannel_configuration_fabric
            - brocade_fibrechannel_configuration_port_configuration
            - brocade_fibrechannel_switch
            - brocade_fibrechannel_trunk_trunk
            - brocade_fibrechannel_trunk_performance
            - brocade_fibrechannel_trunk_trunk_area
            - brocade_time_clock_server
            - brocade_time_time_zone
            - brocade_logging_syslog_server
            - brocade_logging_audit
            - brocade_media_media_rdp
            - brocade_snmp_system
            - brocade_security_ipfilter_rule
            - brocade_security_ipfilter_policy
            - brocade_security_user_config
            - brocade_security_password_cfg
            - brocade_security_security_certificate
            - brocade_snmp_v1_account
            - brocade_snmp_v1_trap
            - brocade_snmp_v3_account
            - brocade_snmp_v3_trap
            - brocade_maps_maps_config
            - brocade_security_sec_crypto_cfg_template_action
            - brocade_security_sshutil_public_key
            - brocade_security_ldap_role_map
        required: false
        default: all
        type: list

'''


EXAMPLES = """

  vars:
    credential:
      fos_ip_addr: "{{fos_ip_addr}}"
      fos_user_name: admin
      fos_password: password
      https: False

  tasks:

  - name: gather facts
    brocade_facts:
      credential: "{{credential}}"
      vfid: -1
      gather_subset:
        - brocade_access_gateway_port_group
        - brocade_access_gateway_n_port_map
        - brocade_access_gateway_f_port_list
        - brocade_access_gateway_device_list
        - brocade_access_gateway_policy
        - brocade_access_gateway_n_port_settings
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
        - brocade_snmp_v1_account
        - brocade_snmp_v1_trap
        - brocade_snmp_v3_account
        - brocade_snmp_v3_trap
        - brocade_maps_maps_config
        - brocade_security_sec_crypto_cfg_template_action
        - brocade_security_sshutil_public_key
        - brocade_security_ldap_role_map

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
Brocade Fibre Channel gather FOS facts
"""


from ansible.module_utils.brocade_connection import login, logout, exit_after_login
from ansible.module_utils.brocade_zoning import defined_get, effective_get, to_human_zoning
from ansible.module_utils.brocade_objects import singleton_get, list_get, to_human_singleton, to_human_list, get_moduleName
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
    "brocade_zoning_simple",
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
    "brocade_security_sec_crypto_cfg_template",
    "brocade_snmp_v1_account",
    "brocade_snmp_v1_trap",
    "brocade_snmp_v3_account",
    "brocade_snmp_v3_trap",
    "brocade_maps_maps_config",
    "brocade_maps_rule",
    "brocade_maps_maps_policy",
    "brocade_security_sec_crypto_cfg_template_action",
    "brocade_security_ldap_role_map"
    ]

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
            module_name = ""

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
            elif area == "brocade_security_sec_crypto_cfg_template":
                module_name = "brocade_security"
                list_name = "sec_crypto_cfg_template"
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
            elif area == "brocade_snmp_v1_account":
                module_name = "brocade_snmp"
                list_name = "v1_account"
                get_list = True
            elif area == "brocade_snmp_v1_trap":
                module_name = "brocade_snmp"
                list_name = "v1_trap"
                get_list = True
            elif area == "brocade_snmp_v3_account":
                module_name = "brocade_snmp"
                list_name = "v3_account"
                get_list = True
            elif area == "brocade_snmp_v3_trap":
                module_name = "brocade_snmp"
                list_name = "v3_trap"
                get_list = True
            elif area == "brocade_maps_maps_config":
                module_name = "brocade_maps"
                obj_name = "maps_config"
                get_singleton = True
            elif area == "brocade_maps_rule":
                module_name = "brocade_maps"
                list_name = "rule"
                get_list = True
            elif area == "brocade_maps_maps_policy":
                module_name = "brocade_maps"
                list_name = "maps_policy"
                get_list = True
            elif area == "brocade_security_sec_crypto_cfg_template_action":
                module_name = "brocade_security"
                obj_name = "sec_crypto_cfg_template_action"
                get_singleton = True
            elif area == "brocade_security_ldap_role_map":
                module_name = "brocade_security"
                list_name = "ldap_role_map"
                get_list = True

            module_name = get_moduleName(fos_version, module_name)
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
                    fos_ip_addr, https, fos_version, auth, vfid, result, timeout)
                if ret_code != 0:
                    exit_after_login(fos_ip_addr, https, auth, result, module, timeout)

                zoning = {}
                zoning["defined-configuration"] = (
                    response["Response"]["defined-configuration"]
                )

                to_human_zoning(zoning["defined-configuration"])

                ret_code, response = effective_get(
                    fos_ip_addr, https, fos_version, auth, vfid, result, timeout)
                if ret_code != 0:
                    exit_after_login(fos_ip_addr, https, auth, result, module, timeout)

                zoning["effective-configuration"] = (
                    response["Response"]["effective-configuration"]
                )

                to_human_zoning(zoning["effective-configuration"])

                facts[area] = zoning
            elif area == "brocade_zoning_simple":
                ret_code, response = defined_get(
                    fos_ip_addr, https, fos_version, auth, vfid, result, timeout)
                if ret_code != 0:
                    exit_after_login(fos_ip_addr, https, auth, result, module, timeout)

                zoning = {}
                zoning["defined-configuration"] = {
                    "aliases": [],
                    "zones": [],
                    "cfgs": []
                }

                if response["Response"]["defined-configuration"]["cfg"] is not None:
                    r_cfgs = response["Response"]["defined-configuration"]["cfg"]
                    if not isinstance(response["Response"]["defined-configuration"]["cfg"], list):
                        r_cfgs = [response["Response"]["defined-configuration"]["cfg"]]
                    for cfg in r_cfgs:
                        cfg_members = cfg["member-zone"]["zone-name"]
                        if not isinstance(cfg["member-zone"]["zone-name"], list):
                            cfg_members = [cfg["member-zone"]["zone-name"]]
                        zoning["defined-configuration"]["cfgs"].append(
                            {
                                "name": cfg["cfg-name"],
                                "members": cfg_members
                            }
                        )


                if response["Response"]["defined-configuration"]["alias"] is not None:
                    r_aliases = response["Response"]["defined-configuration"]["alias"]
                    if not isinstance(response["Response"]["defined-configuration"]["alias"], list):
                        r_aliases = [response["Response"]["defined-configuration"]["alias"]]
                    for alias in r_aliases:
                        alias_members = alias["member-entry"]["alias-entry-name"]
                        if not isinstance(alias["member-entry"]["alias-entry-name"], list):
                            alias_members = [alias["member-entry"]["alias-entry-name"]]
                        zoning["defined-configuration"]["aliases"].append(
                            {
                                "name": alias["alias-name"],
                                "members": alias_members
                            }
                        )

                if response["Response"]["defined-configuration"]["zone"] is not None:
                    r_zones = response["Response"]["defined-configuration"]["zone"]
                    if not isinstance(response["Response"]["defined-configuration"]["zone"], list):
                        r_zones = [response["Response"]["defined-configuration"]["zone"]]
                    for zone in r_zones:
                        zone_members = zone["member-entry"]["entry-name"]
                        if not isinstance(zone["member-entry"]["entry-name"], list):
                            zone_members = [zone["member-entry"]["entry-name"]]
                        if "principal-entry-name" in zone["member-entry"]:
                            pzone_members = zone["member-entry"]["principal-entry-name"]
                            if not isinstance(zone["member-entry"]["principal-entry-name"], list):
                                pzone_members = [zone["member-entry"]["principal-entry-name"]]
                            zoning["defined-configuration"]["zones"].append(
                                {
                                    "name": zone["zone-name"],
                                    "members": zone_members,
                                    "principal_members": pzone_members
                                }
                            )
                        else:
                            zoning["defined-configuration"]["zones"].append(
                                {
                                    "name": zone["zone-name"],
                                    "members": zone_members
                                }
                            )

                ret_code, response = effective_get(
                    fos_ip_addr, https, fos_version, auth, vfid, result, timeout)
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
