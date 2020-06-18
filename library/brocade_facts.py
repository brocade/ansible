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
          fos_ip_addr: ip address of the FOS switch
          fos_user_name: login name of FOS switch REST API
          fos_password: password of FOS switch REST API
          https: True for HTTPS, self for self-signed HTTPS, or False for HTTP
          ssh_hostkeymust: hostkeymust arguement for ssh attributes only. Default True.
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
    gather_subset:
        description:
        - list of areas to be gathered. If this option is missing,
          all areas' facts will be gathered. Same behavior applies
          if "all" is listed as part of gather_subset
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
        - brocade_chassis
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
from ansible.module_utils.brocade_interface import fc_port_get, fc_port_stats_get, to_human_fc
from ansible.module_utils.brocade_zoning import defined_get, effective_get, to_human_zoning
from ansible.module_utils.brocade_chassis import chassis_get, to_human_chassis
from ansible.module_utils.brocade_fibrechannel_configuration import fabric_get, to_human_fabric, port_configuration_get, to_human_port_configuration
from ansible.module_utils.brocade_fibrechannel_switch import fc_switch_get, to_human_switch
from ansible.module_utils.brocade_time import clock_server_get, to_human_clock_server
from ansible.module_utils.brocade_time import time_zone_get, to_human_time_zone
from ansible.module_utils.brocade_logging import syslog_server_get, to_human_syslog_server
from ansible.module_utils.brocade_logging import audit_get, to_human_audit
from ansible.module_utils.brocade_snmp import system_get, to_human_system
from ansible.module_utils.brocade_security import ipfilter_rule_get, to_human_ipfilter_rule, ipfilter_policy_get, to_human_ipfilter_policy, user_config_get, to_human_user_config
from ansible.module_utils.basic import AnsibleModule


valid_areas = [
    "brocade_zoning",
    "brocade_interface_fibrechannel",
    "brocade_chassis",
    "brocade_fibrechannel_configuration_fabric",
    "brocade_fibrechannel_configuration_port_configuration",
    "brocade_fibrechannel_switch",
    "brocade_time_clock_server",
    "brocade_time_time_zone",
    "brocade_logging_syslog_server",
    "brocade_logging_audit",
    "brocade_snmp_system",
    "brocade_security_ipfilter_rule",
    "brocade_security_ipfilter_policy",
    "brocade_security_user_config",
    ]


def main():
    """
    Main function
    """

    argument_spec = dict(
        credential=dict(required=True, type='dict', no_log=True),
        vfid=dict(required=False, type='int'),
        throttle=dict(required=False, type='float'),
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
    vfid = input_params['vfid']
    gather_subset = input_params['gather_subset']
    result = {"changed": False}

    if vfid is None:
        vfid = 128

    ret_code, auth, fos_version = login(fos_ip_addr,
                           fos_user_name, fos_password,
                           https, throttle, result)
    if ret_code != 0:
        module.exit_json(**result)

    facts = {}

    facts['ssh_hostkeymust'] = ssh_hostkeymust

    for area in valid_areas:
        if (
                gather_subset is None or area in gather_subset or
                "all" in gather_subset
        ):
            if area == "brocade_interface_fibrechannel":
                ret_code, response = fc_port_get(
                    fos_ip_addr, https, auth, vfid, result)
                if ret_code != 0:
                    exit_after_login(fos_ip_addr, https, auth, result, module)

                interface = {}
                interface["fibrechannel"] = (
                    response["Response"]["fibrechannel"]
                )

                for port in interface["fibrechannel"]:
                    to_human_fc(port)

                ret_code, response = fc_port_stats_get(
                    fos_ip_addr, https, auth, vfid, result)
                if ret_code != 0:
                    exit_after_login(fos_ip_addr, https, auth, result, module)

                interface["fibrechannel-statistics"] = (
                    response["Response"]["fibrechannel-statistics"]
                )

                facts[area] = interface

            if area == "brocade_zoning":
                ret_code, response = defined_get(
                    fos_ip_addr, https, auth, vfid, result)
                if ret_code != 0:
                    exit_after_login(fos_ip_addr, https, auth, result, module)

                zoning = {}
                zoning["defined-configuration"] = (
                    response["Response"]["defined-configuration"]
                )

                ret_code, response = effective_get(
                    fos_ip_addr, https, auth, vfid, result)
                if ret_code != 0:
                    exit_after_login(fos_ip_addr, https, auth, result, module)

                zoning["effective-configuration"] = (
                    response["Response"]["effective-configuration"]
                )

                to_human_zoning(zoning["effective-configuration"])

                facts[area] = zoning

            if area == "brocade_chassis":
                ret_code, response = chassis_get(fos_user_name, fos_password,
                    fos_ip_addr, fos_version, https, auth, vfid, result,
                    ssh_hostkeymust)
                if ret_code != 0:
                    exit_after_login(fos_ip_addr, https, auth, result, module)

                to_human_chassis(response["Response"]["chassis"])

                facts[area] = response["Response"]["chassis"]

            if area == "brocade_fibrechannel_configuration_fabric":
                ret_code, response = fabric_get(fos_user_name, fos_password,
                    fos_ip_addr, fos_version, https, auth, vfid, result,
                    ssh_hostkeymust)
                if ret_code != 0:
                    exit_after_login(fos_ip_addr, https, auth, result, module)

                to_human_fabric(response["Response"]["fabric"])

                facts[area] = response["Response"]["fabric"]

            if area == "brocade_fibrechannel_configuration_port_configuration":
                ret_code, response = port_configuration_get(fos_user_name,
                    fos_password,
                    fos_ip_addr, fos_version, https, auth, vfid, result,
                    ssh_hostkeymust)
                if ret_code != 0:
                    exit_after_login(fos_ip_addr, https, auth, result, module)

                to_human_port_configuration(response["Response"]["port-configuration"])

                facts[area] = response["Response"]["port-configuration"]

            if area == "brocade_fibrechannel_switch":
                ret_code, response = fc_switch_get(fos_user_name, fos_password,
                    fos_ip_addr, fos_version, https, auth, vfid, result,
                    ssh_hostkeymust)
                if ret_code != 0:
                    exit_after_login(fos_ip_addr, https, auth, result, module)

                to_human_switch(response["Response"]["fibrechannel-switch"])

                facts[area] = response["Response"]["fibrechannel-switch"]

            if area == "brocade_time_clock_server":
                ret_code, response = clock_server_get(
                    fos_ip_addr, https, auth, vfid, result)
                if ret_code != 0:
                    exit_after_login(fos_ip_addr, https, auth, result, module)

                to_human_clock_server(response["Response"]["clock-server"])

                facts[area] = response["Response"]["clock-server"]

            if area == "brocade_time_time_zone":
                ret_code, response = time_zone_get(
                    fos_ip_addr, https, auth, vfid, result)
                if ret_code != 0:
                    exit_after_login(fos_ip_addr, https, auth, result, module)

                to_human_time_zone(response["Response"]["time-zone"])

                facts[area] = response["Response"]["time-zone"]

            if area == "brocade_logging_syslog_server":
                ret_code, response = syslog_server_get(
                    fos_ip_addr, https, auth, vfid, result)
                if ret_code != 0:
                    exit_after_login(fos_ip_addr, https, auth, result, module)

                if isinstance(response["Response"]["syslog-server"], list):
                    servers = response["Response"]["syslog-server"]
                else:
                    servers = [response["Response"]["syslog-server"]]

                for server in servers:
                    to_human_syslog_server(server)

                facts[area] = servers

            if area == "brocade_logging_audit":
                ret_code, response = audit_get(
                    fos_ip_addr, https, auth, vfid, result)
                if ret_code != 0:
                    exit_after_login(fos_ip_addr, https, auth, result, module)

                to_human_audit(response["Response"]["audit"])

                facts[area] = response["Response"]["audit"]

            if area == "brocade_snmp_system":
                ret_code, response = system_get(fos_user_name, fos_password,
                    fos_ip_addr, fos_version, https, auth, vfid, result)
                if ret_code != 0:
                    exit_after_login(fos_ip_addr, https, auth, result, module)

                to_human_system(response["Response"]["system"])

                facts[area] = response["Response"]["system"]

            if area == "brocade_security_ipfilter_rule":
                ret_code, response = ipfilter_rule_get(
                    fos_ip_addr, https, auth, vfid, result)
                if ret_code != 0:
                    exit_after_login(fos_ip_addr, https, auth, result, module)

                for rule in response["Response"]["ipfilter-rule"]:
                    to_human_ipfilter_rule(rule)

                facts[area] = response["Response"]["ipfilter-rule"]

            if area == "brocade_security_ipfilter_policy":
                ret_code, response = ipfilter_policy_get(
                    fos_ip_addr, https, auth, vfid, result)
                if ret_code != 0:
                    exit_after_login(fos_ip_addr, https, auth, result, module)

                for rule in response["Response"]["ipfilter-policy"]:
                    to_human_ipfilter_policy(rule)

                facts[area] = response["Response"]["ipfilter-policy"]

            if area == "brocade_security_user_config":
                ret_code, response = user_config_get(
                    fos_ip_addr, https, auth, vfid, result)
                if ret_code != 0:
                    exit_after_login(fos_ip_addr, https, auth, result, module)

                for rule in response["Response"]["user-config"]:
                    to_human_user_config(rule)

                facts[area] = response["Response"]["user-config"]

    result["ansible_facts"] = facts

    logout(fos_ip_addr, https, auth, result)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
