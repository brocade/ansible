# Copyright 2019 Broadcom. All rights reserved.
# The term 'Broadcom' refers to Broadcom Inc. and/or its subsidiaries.
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import (absolute_import, division, print_function)
from ansible.module_utils.brocade_url import url_get_to_dict, url_patch, full_url_get, url_patch_single_object, url_post, url_delete, url_post_resp, ERROR_LIST_EMPTY
from ansible.module_utils.brocade_yang import yang_to_human, human_to_yang, str_to_yang, str_to_human, generate_diff, is_full_human
from ansible.module_utils.brocade_ssh import ssh_and_configure
from ansible.module_utils.brocade_interface import to_fos_fc, to_human_fc
from ansible.module_utils.brocade_chassis import chassis_get, chassis_patch
from ansible.module_utils.brocade_fibrechannel_configuration import fabric_get, fabric_patch, port_configuration_get, port_configuration_patch
from ansible.module_utils.brocade_fibrechannel_switch import to_human_switch, to_fos_switch, fc_switch_get, fc_switch_patch
from ansible.module_utils.brocade_interface import to_human_fc, to_fos_fc, fc_port_get, fc_port_patch
from ansible.module_utils.brocade_security import user_config_patch
from ansible.module_utils.brocade_access_gateway import to_human_access_gateway_policy, to_fos_access_gateway_policy
from ansible.module_utils.brocade_snmp import v1_trap_patch, v3_trap_patch
from ansible.module_utils.brocade_connection import login, logout, exit_after_login
import base64

__metaclass__ = type


"""
Brocade logging utils
"""


REST_PREFIX = "/rest/running/"
OP_PREFIX = "/rest/operations/"


def to_human_singleton(module_name, obj_name, attributes):
    yang_to_human(attributes)

    for k, v in attributes.items():
        if v == "true":
            attributes[k] = True
        elif v == "false":
            attributes[k] = False

    if module_name == "brocade_time" and obj_name == "clock_server":
        if "ntp_server_address" in attributes and "server_address" in attributes["ntp_server_address"]:
            if not isinstance(attributes["ntp_server_address"]["server_address"], list):
                new_list = []
                new_list.append(attributes["ntp_server_address"]["server_address"])
                attributes["ntp_server_address"]["server_address"] = new_list

    if module_name == "brocade_access_gateway" and obj_name == "policy":
        to_human_access_gateway_policy(attributes)


def to_fos_singleton(module_name, obj_name, attributes, result):
    human_to_yang(attributes)

    for k, v in attributes.items():
        # if going to fos, we need to encode password
        if module_name == "brocade_security" and obj_name == "password":
            if k == "old-password":
                attributes[k] = base64.b64encode(attributes[k].encode('ascii')).decode('utf-8')
            if k == "new-password":
                attributes[k] = base64.b64encode(attributes[k].encode('ascii')).decode('utf-8')

        if module_name == "brocade_security" and (obj_name == "security_certificate_action" or obj_name == "sshutil_public_key_action"):
            if k == "remote-user-password":
                attributes[k] = base64.b64encode(attributes[k].encode('ascii')).decode('utf-8')

    if module_name == "brocade_access_gateway" and obj_name == "policy":
        to_fos_access_gateway_policy(attributes, result)

    for k, v in attributes.items():
        if isinstance(v, bool):
            if v == True:
                attributes[k] = "true"
            else:
                attributes[k] = "false"

    return 0


def singleton_get(login, password, fos_ip_addr, module_name, obj_name, fos_version, is_https, auth, vfid, result, ssh_hostkeymust, timeout):
    """
        retrieve existing user config configuration 

        :param fos_ip_addr: ip address of FOS switch
        :type fos_ip_addr: str
        :param is_https: indicate to use HTTP or HTTPS
        :type is_https: bool
        :param auth: authorization struct from login
        :type struct: dict
        :param result: dict to keep track of execution msgs
        :type result: dict
        :return: code to indicate failure or success
        :rtype: int
        :return: dict of ipfilter policy configurations
        :rtype: dict
    """
    if module_name == "brocade_chassis" and obj_name == "chassis":
        return chassis_get(login, password, fos_ip_addr, fos_version, is_https, auth, vfid, result, ssh_hostkeymust, timeout)

    if module_name == "brocade_fibrechannel_configuration" and obj_name == "fabric":
        return fabric_get(login, password, fos_ip_addr, fos_version, is_https, auth, vfid, result, ssh_hostkeymust, timeout)

    if module_name == "brocade_fibrechannel_configuration" and obj_name == "port_configuration":
        return port_configuration_get(login, password, fos_ip_addr, fos_version, is_https, auth, vfid, result, ssh_hostkeymust, timeout)

    # get is not support for these modules. Just return empty
    if module_name == "brocade_security" and obj_name == "security_certificate_action":
        return 0, ({"Response" : {str_to_yang(obj_name): {}}})
    if module_name == "brocade_security" and obj_name == "security_certificate_generate":
        return 0, ({"Response" : {str_to_yang(obj_name): {}}})
    if module_name == "brocade_security" and obj_name == "sshutil_public_key_action":
        return 0, ({"Response" : {str_to_yang(obj_name): {}}})

    full_url, validate_certs = full_url_get(is_https,
                                            fos_ip_addr,
                                            REST_PREFIX + module_name + "/" + obj_name)

    ret, resp = url_get_to_dict(fos_ip_addr, is_https, auth, vfid,
                                result, full_url, timeout)

    if ret == ERROR_LIST_EMPTY:
        # return empty dict. GET isn't supported
        return 0, ({"Response" : {str_to_yang(obj_name): {}}})

    return ret, resp


def to_human_list(module_name, list_name, attributes_list, result):
    for attributes in attributes_list:
        yang_to_human(attributes)

        for k, v in attributes.items():
            if v == "true":
                attributes[k] = True
            elif v == "false":
                attributes[k] = False

        if module_name == "brocade_interface" and list_name == "fibrechannel":
            to_human_fc(attributes)

        if module_name == "brocade_snmp" and list_name == "v3_account":
            if "authentication_password" in attributes:
                pword = attributes["authentication_password"]
                if str(pword) != "None":
                    attributes["authentication_password"] = base64.b64decode(pword)
            if "privacy_password" in attributes:
                pword = attributes["privacy_password"]
                if str(pword) != "None":
                    attributes["privacy_password"] = base64.b64decode(pword)

        if module_name == "brocade_security" and list_name == "user_config":
            if "virtual_fabric_role_id_list" in attributes and "role_id" in attributes["virtual_fabric_role_id_list"]:
                if not isinstance(attributes["virtual_fabric_role_id_list"]["role_id"], list):
                    new_list = []
                    new_list.append(attributes["virtual_fabric_role_id_list"]["role_id"])
                    attributes["virtual_fabric_role_id_list"]["role_id"] = new_list

        if module_name == "brocade_fibrechannel_switch" and list_name == "fibrechannel_switch":

            to_human_switch(attributes)

            if "dns_servers" in attributes:
                if attributes["dns_servers"] is not None and "dns_server" in attributes["dns_servers"]:
                    if not isinstance(attributes["dns_servers"]["dns_server"], list):
                        new_list = []
                        new_list.append(attributes["dns_servers"]["dns_server"])
                        attributes["dns_servers"]["dns_server"] = new_list

            if "ip_address" in attributes:
                if attributes["ip_address"] is not None and "ip_address" in attributes["ip_address"]:
                    if not isinstance(attributes["ip_address"]["ip_address"], list):
                        new_list = []
                        new_list.append(attributes["ip_address"]["ip_address"])
                        attributes["ip_address"]["ip_address"] = new_list

            if "ip_static_gateway_list" in attributes:
                if attributes["ip_static_gateway_list"] is not None and "ip_static_gateway" in attributes["ip_static_gateway_list"]:
                    if not isinstance(attributes["ip_static_gateway_list"]["ip_static_gateway"], list):
                        new_list = []
                        new_list.append(attributes["ip_static_gateway_list"]["ip_static_gateway"])
                        attributes["ip_static_gateway_list"]["ip_static_gateway"] = new_list

        if module_name == "brocade_access_gateway" and list_name == "port_group":
            if "port_group_n_ports" in attributes:
                if attributes["port_group_n_ports"] is not None and "n_port" in attributes["port_group_n_ports"]:
                    if not isinstance(attributes["port_group_n_ports"]["n_port"], list):
                        new_list = []
                        new_list.append(attributes["port_group_n_ports"]["n_port"])
                        attributes["port_group_n_ports"]["n_port"] = new_list

            if "port_group_f_ports" in attributes:
                if attributes["port_group_f_ports"] is not None and "f_port" in attributes["port_group_f_ports"]:
                    if not isinstance(attributes["port_group_f_ports"]["f_port"], list):
                        new_list = []
                        new_list.append(attributes["port_group_f_ports"]["f_port"])
                        attributes["port_group_f_ports"]["f_port"] = new_list
                        
        if module_name == "brocade_access_gateway" and list_name == "n_port_map":
            if "configured_f_port_list" in attributes:
                if attributes["configured_f_port_list"] is not None and "f_port" in attributes["configured_f_port_list"]:
                    if not isinstance(attributes["configured_f_port_list"]["f_port"], list):
                        new_list = []
                        new_list.append(attributes["configured_f_port_list"]["f_port"])
                        attributes["configured_f_port_list"]["f_port"] = new_list



def to_fos_list(module_name, list_name, attributes_list, result):
    for attributes in attributes_list:
        human_to_yang(attributes)

        if module_name == "brocade_snmp" and list_name == "v3_account":
            if "authentication-password" in attributes:
                pword = attributes["authentication-password"]
                if str(pword) != "None":
                    attributes["authentication-password"] = base64.b64encode(pword.encode('ascii')).decode('utf-8')
            if "privacy-password" in attributes:
                pword = attributes["privacy-password"]
                if str(pword) != "None":
                    attributes["privacy-password"] = base64.b64encode(pword.encode('ascii')).decode('utf-8')

        if module_name == "brocade_interface" and list_name == "fibrechannel":
            to_fos_fc(attributes, result)

        if module_name == "brocade_fibrechannel_switch" and list_name == "fibrechannel_switch":
            to_fos_switch(attributes, result)

        if module_name == "brocade_security" and list_name == "user_config":
            if "password" in attributes:
                pword = attributes["password"]
                if str(pword) != "None":
                    attributes["password"] = base64.b64encode(pword.encode('ascii')).decode('utf-8')

        for k, v in attributes.items():
            if isinstance(v, bool):
                if v == True:
                    attributes[k] = "true"
                else:
                    attributes[k] = "false"

    return 0

list_keys = {
    "brocade_access_gateway": {
        "port_group" : ["port_group_id"],
        "n_port_map" : ["n_port"],
    },
    "brocade_extension_ip_route": {
        "extension_ip_route" : ["name", "dp_id", "ip_address", "ip_prefix_length"],
    },
    "brocade_extension_ipsec_policy": {
        "extension_ipsec_policy" : ["policy_name"],
    },
    "brocade_extension_tunnel": {
        "extension_tunnel" : ["name"],
        "extension_circuit" : ["name", "circuit_id"],
    },
    "brocade_fabric": {
        "fabric_switch" : ["name"],
    },
    "brocade_fdmi": {
        "hba" : ["hba_id"],
        "port" : ["port_name"],
    },
    "brocade_fibrechannel_diagnostics": {
        "fibrechannel_diagnostics" : ["name"],
    },
    "brocade_fibrechannel_logical_switch": {
        "fibrechannel_logical_switch" : ["fabric_id"],
    },
    "brocade_fibrechannel_switch": {
        "fibrechannel_switch" : ["name"],
    },
    "brocade_fibrechannel_trunk": {
        "trunk_area" : ["trunk_index"],
    },
    "ficon": {
        "ficon_logical_path" : ["link_address", "channel_image_id"],
    },
    "brocade_fru": {
        "blade" : ["slot_number"],
    },
    "brocade_interface": {
        "fibrechannel" : ["name"],
        "fibrechannel_statistics" : ["name"],
        "extension_ip_interface" : ["name", "ip_address", "dp_id"],
        "gigabitethernet" : ["name"],
        "gigabitethernet_statistics" : ["name"],
    },
    "brocade_license": {
        "license" : ["name"],
    },
    "brocade_logging": {
        "syslog_server" : ["server"],
        "raslog" : ["message_id"],
        "raslog_module" : ["module_id"],
        "log_quiet_control" : ["log_type"],
    },
    "brocade_maps": {
        "paused_cfg" : ["group_type"],
        "group" : ["name"],
        "rule" : ["name"],
        "maps_policy" : ["name"],
    },
    "brocade_media": {
        "media_rdp" : ["name"],
    },
    "brocade_module_version": {
    },
    "brocade_name_server": {
        "fibrechannel_name_server" : ["port_id"],
    },
    "brocade_security": {
        "ipfilter_policy" : ["name"],
        "ipfilter_rule" : ["policy_name", "index"],
        "user_specific_password_cfg" : ["user_name"],
        "user_config" : ["name"],
        "radius_server" : ["server"],
        "tacacs_server" : ["server"],
        "ldap_server" : ["server"],
        "ldap_role_map" : ["ldap_role"],
        "sshutil_key" : ["algorithm_type", "key_type"],
        "sshutil_public_key" : ["user_name"],
    },
    "brocade_snmp": {
        "mib_capability" : ["mib_name"],
        "trap_capability" : ["trap_name"],
        "v1_account" : ["index"],
        "v1_trap" : ["index"],
        "v3_account" : ["index"],
        "v3_trap" : ["trap_index"],
        "access_control" : ["index"],
    },
    "brocade_module_id": {
        "my_list_name" : ["my_key_leaf"],
    },
}

def list_entry_keys_matched(e1, e2, module_name, list_name):
    keys = list_entry_keys(module_name, list_name)

    matched = 0
    for key in keys:
        if key in e1 and key in e2 and str(e1[key]) == str(e2[key]):
            matched = matched + 1

    if matched == len(keys):
        return True

    return False

def list_entry_keys(module_name, list_name):
    if module_name in list_keys:
        if list_name in list_keys[module_name]:
            return list_keys[module_name][list_name]

    return []

def list_get(login, password, fos_ip_addr, module_name, list_name, fos_version, is_https, auth, vfid, result, ssh_hostkeymust, timeout):
    if module_name == "brocade_fibrechannel_switch" and list_name == "fibrechannel_switch":
        return fc_switch_get(login, password, fos_ip_addr, fos_version, is_https, auth, vfid, result, ssh_hostkeymust, timeout)
    if module_name == "brocade_interface" and list_name == "fibrechannel":
        return fc_port_get(fos_ip_addr, is_https, auth, vfid, result, timeout)

    return singleton_get(login, password, fos_ip_addr, module_name, list_name, fos_version, is_https, auth, vfid, result, ssh_hostkeymust, timeout)


def singleton_xml_str(result, obj_name, attributes):
    obj_name_yang = str_to_yang(obj_name)
    xml_str = ""

    xml_str = xml_str + "<" + obj_name_yang + ">"

    for k, v in attributes.items():
        xml_str = xml_str + "<" + k + ">"

        if isinstance(v, dict):
            for k1, v1 in v.items():
                if isinstance(v1, list):
                    for entry in v1:
                        xml_str = xml_str + "<" + k1 + ">" + str(entry) + "</" + k1 + ">"
                else:
                    xml_str = xml_str + "<" + k1 + ">" + str(v1) + "</" + k1 + ">"
        else:
            xml_str = xml_str + str(v)

        xml_str = xml_str + "</" + k + ">"

    xml_str = xml_str + "</" + obj_name_yang + ">"

    return xml_str


def singleton_patch(login, password, fos_ip_addr, module_name, obj_name, fos_version, is_https, auth, vfid, result, new_attributes, ssh_hostkeymust, timeout):
    """
        update existing user config configurations

        :param fos_ip_addr: ip address of FOS switch
        :type fos_ip_addr: str
        :param is_https: indicate to use HTTP or HTTPS
        :type is_https: bool
        :param auth: authorization struct from login
        :type struct: dict
        :param result: dict to keep track of execution msgs
        :type result: dict
        :param diff_attributes: list of attributes for update
        :type ports: dict
        :return: code to indicate failure or success
        :rtype: int
        :return: list of dict of chassis configurations
        :rtype: list
    """
    if module_name == "brocade_chassis" and obj_name == "chassis":
        return chassis_patch(login, password, fos_ip_addr, fos_version, is_https, auth, vfid, result, new_attributes, ssh_hostkeymust, timeout)

    if module_name == "brocade_fibrechannel_configuration" and obj_name == "fabric":
        return fabric_patch(login, password, fos_ip_addr, fos_version, is_https, auth, vfid, result, new_attributes, ssh_hostkeymust, timeout)

    if module_name == "brocade_fibrechannel_configuration" and obj_name == "port_configuration":
        return port_configuration_patch(login, password, fos_ip_addr, fos_version, is_https, auth, vfid, result, new_attributes, ssh_hostkeymust, timeout)

    full_url, validate_certs = full_url_get(is_https,
                                            fos_ip_addr,
                                            REST_PREFIX + module_name + "/" + obj_name)

    xml_str = singleton_xml_str(result, obj_name, new_attributes)

    result["patch_obj_str"] = xml_str

    if module_name == "brocade_security" and obj_name == "security_certificate_generate":
        return url_post(fos_ip_addr, is_https, auth, vfid, result,
                        full_url, xml_str, timeout)

    return url_patch(fos_ip_addr, is_https, auth, vfid, result,
                     full_url, xml_str, timeout)


def list_xml_str(result, module_name, list_name, entries):
    list_name_yang = str_to_yang(list_name)
    xml_str = ""

    for entry in entries:
        xml_str = xml_str + "<" + list_name_yang + ">"

        # add the key entries first
        for k, v in entry.items():
            if str_to_human(k) in list_entry_keys(module_name, list_name):
                result[k] = "key identified"
                xml_str = xml_str + "<" + k + ">" + str(v) + "</" + k + ">"

        # add non key entries next
        for k, v in entry.items():
            if str_to_human(k) not in list_entry_keys(module_name, list_name):
                xml_str = xml_str + "<" + k + ">"

                if isinstance(v, dict):
                    for k1, v1 in v.items():
                        if isinstance(v1, list):
                            for entry in v1:
                                xml_str = xml_str + "<" + k1 + ">" + str(entry) + "</" + k1 + ">"
                        else:
                            if v1 == None:
                                xml_str = xml_str + "<" + k1 + "></" + k1 + ">"
                            else:
                                xml_str = xml_str + "<" + k1 + ">" + str(v1) + "</" + k1 + ">"
                else:
                    if v == None:
                        xml_str = xml_str
                    else:
                        xml_str = xml_str + str(v)

                xml_str = xml_str + "</" + k + ">"

        xml_str = xml_str + "</" + list_name_yang + ">"

    return xml_str


def list_patch(login, password, fos_ip_addr, module_name, list_name, fos_version, is_https, auth, vfid, result, entries, ssh_hostkeymust, timeout):
    """
        update existing user config configurations

        :param fos_ip_addr: ip address of FOS switch
        :type fos_ip_addr: str
        :param is_https: indicate to use HTTP or HTTPS
        :type is_https: bool
        :param auth: authorization struct from login
        :type struct: dict
        :param result: dict to keep track of execution msgs
        :type result: dict
        :param diff_attributes: list of attributes for update
        :type ports: dict
        :return: code to indicate failure or success
        :rtype: int
        :return: list of dict of chassis configurations
        :rtype: list
    """
    if module_name == "brocade_fibrechannel_switch" and list_name == "fibrechannel_switch":
        return fc_switch_patch(login, password, fos_ip_addr, fos_version, is_https, auth, vfid, result, entries[0], ssh_hostkeymust, timeout)
    if module_name == "brocade_interface" and list_name == "fibrechannel":
        return fc_port_patch(fos_ip_addr, is_https, auth, vfid, result, entries, timeout)
    if module_name == "brocade_security" and list_name == "user_config":
        return user_config_patch(login, password, fos_ip_addr, fos_version, is_https, auth, vfid, result, entries, ssh_hostkeymust, timeout)

    if module_name == "brocade_snmp" and list_name == "v1_trap":
        new_entries = v1_trap_patch(login, password, fos_ip_addr, fos_version, is_https, auth, vfid, result, entries, ssh_hostkeymust, timeout)

        if len(new_entries) == 0:
            return 0

        entries = new_entries

    if module_name == "brocade_snmp" and list_name == "v3_trap":
        new_entries = v3_trap_patch(login, password, fos_ip_addr, fos_version, is_https, auth, vfid, result, entries, ssh_hostkeymust, timeout)

        if len(new_entries) == 0:
            return 0

        entries = new_entries

    full_url, validate_certs = full_url_get(is_https,
                                            fos_ip_addr,
                                            REST_PREFIX + module_name + "/" + list_name)

    xml_str = list_xml_str(result, module_name, list_name, entries)

    result["patch_str"] = xml_str

    # AG always expect nport and fports to be removed from another
    # none default port group before being added. So, we go through
    # an port group that has nport or fport list being updated,
    # clean them out first, then do the normal patch to update to the
    # final list
    if module_name == "brocade_access_gateway" and list_name == "port_group":
        empty_port_groups = []
        for port_group in entries:
            if "port-group-n-ports" in port_group and port_group["port-group-n-ports"] is not None and "n-port" in port_group["port-group-n-ports"] and port_group["port-group-n-ports"]["n-port"] is not None:
                empty_port_groups.append({"port-group-id":port_group["port-group-id"], "port-group-n-ports":{"n-port": None}})
            if "port-group-f-ports" in port_group and port_group["port-group-f-ports"] is not None and "f-port" in port_group["port-group-f-ports"] and port_group["port-group-f-ports"]["f-port"] is not None:
                empty_port_groups.append({"port-group-id":port_group["port-group-id"], "port-group-f-ports":{"f-port": None}})
        if len(empty_port_groups) > 0:
            empty_xml_str = list_xml_str(result, module_name, list_name, empty_port_groups)

            result["patch_str_empty_ag"] = empty_xml_str
            empty_patch_result = url_patch(fos_ip_addr, is_https, auth, vfid,
                    result, full_url, empty_xml_str, timeout)
            result["patch_str_empty_ag_result"] = empty_patch_result

    # AG always expect fports to be removed from another nport before
    # being added. to another nport So, we go through
    # an nport map that has fport list being updated,
    # clean them out first, then do the normal patch to update to the
    # final list
    if module_name == "brocade_access_gateway" and list_name == "n_port_map":
        empty_n_port_maps = []
        for n_port_map in entries:
            if "configured-f-port-list" in n_port_map and "f-port" in n_port_map["configured-f-port-list"] and n_port_map["configured-f-port-list"]["f-port"] is not None:
                empty_n_port_maps.append({"n-port":n_port_map["n-port"], "configured-f-port-list":{"f-port": None}})
        if len(empty_n_port_maps) > 0:
            empty_xml_str = list_xml_str(result, module_name, list_name, empty_n_port_maps)

            result["patch_str_empty_ag"] = empty_xml_str
            url_patch(fos_ip_addr, is_https, auth, vfid, result,
                      full_url, empty_xml_str, timeout)

    return(url_patch(fos_ip_addr, is_https, auth, vfid, result,
                     full_url, xml_str, timeout))


def list_post(login, password, fos_ip_addr, module_name, list_name, fos_version, is_https, auth, vfid, result, entries, ssh_hostkeymust, timeout):
    """
        update existing user config configurations

        :param fos_ip_addr: ip address of FOS switch
        :type fos_ip_addr: str
        :param is_https: indicate to use HTTP or HTTPS
        :type is_https: bool
        :param auth: authorization struct from login
        :type struct: dict
        :param result: dict to keep track of execution msgs
        :type result: dict
        :param diff_attributes: list of attributes for update
        :type ports: dict
        :return: code to indicate failure or success
        :rtype: int
        :return: list of dict of chassis configurations
        :rtype: list
    """
    full_url, validate_certs = full_url_get(is_https,
                                            fos_ip_addr,
                                            REST_PREFIX + module_name + "/" + list_name)

    xml_str = list_xml_str(result, module_name, list_name, entries)

    result["post_str"] = xml_str

    return url_post(fos_ip_addr, is_https, auth, vfid, result,
                     full_url, xml_str, timeout)


def list_delete(login, password, fos_ip_addr, module_name, list_name, fos_version, is_https, auth, vfid, result, entries, ssh_hostkeymust, timeout):
    """
        update existing user config configurations

        :param fos_ip_addr: ip address of FOS switch
        :type fos_ip_addr: str
        :param is_https: indicate to use HTTP or HTTPS
        :type is_https: bool
        :param auth: authorization struct from login
        :type struct: dict
        :param result: dict to keep track of execution msgs
        :type result: dict
        :param diff_attributes: list of attributes for update
        :type ports: dict
        :return: code to indicate failure or success
        :rtype: int
        :return: list of dict of chassis configurations
        :rtype: list
    """
    full_url, validate_certs = full_url_get(is_https,
                                            fos_ip_addr,
                                            REST_PREFIX + module_name + "/" + list_name)

    xml_str = list_xml_str(result, module_name, list_name, entries)

    result["delete_str"] = xml_str

    return url_delete(fos_ip_addr, is_https, auth, vfid, result,
                     full_url, xml_str, timeout)


def singleton_helper(module, fos_ip_addr, fos_user_name, fos_password, https, ssh_hostkeymust, throttle, vfid, module_name, obj_name, attributes, result, timeout):

    if not is_full_human(attributes, result):
        module.exit_json(**result)

    if vfid is None:
        vfid = 128

    ret_code, auth, fos_version = login(fos_ip_addr,
                           fos_user_name, fos_password,
                           https, throttle, result, timeout)
    if ret_code != 0:
        module.exit_json(**result)

    result['ssh_hostkeymust'] = ssh_hostkeymust

    ret_code, response = singleton_get(fos_user_name, fos_password, fos_ip_addr,
                                       module_name, obj_name, fos_version,
                                       https, auth, vfid, result,
                                       ssh_hostkeymust, timeout)
    if ret_code != 0:
        exit_after_login(fos_ip_addr, https, auth, result, module, timeout)

    resp_attributes = response["Response"][str_to_yang(obj_name)]

    to_human_singleton(module_name, obj_name, resp_attributes)

    diff_attributes = generate_diff(result, resp_attributes, attributes)

    # any object specific special processing
    if module_name == "brocade_maps" and obj_name == "maps_config":
        # relay_ip_address and domain_name needs to be specifid
        # at the same time based on FOS REST requirements
        if "relay_ip_address" in diff_attributes and "domain_name" not in diff_attributes:
            diff_attributes["domain_name"] = resp_attributes["domain_name"]
            result["kept the same"] = "domain_name"
        elif "relay_ip_address" not in diff_attributes and "domain_name" in diff_attributes:
            diff_attributes["relay_ip_address"] = resp_attributes["relay_ip_address"]
            result["kept the same"] = "relay_ip_address"

        if "relay_ip_address" in diff_attributes and diff_attributes["relay_ip_address"] == None:
            result["failed"] = True
            result['msg'] = "must specify relay_ip_address if configured empty"
            exit_after_login(fos_ip_addr, https, auth, result, module, timeout)
        elif "domain_name" in diff_attributes and diff_attributes["domain_name"] == None:
            result["failed"] = True
            result['msg'] = "must specify domain_name if configured empty"
            exit_after_login(fos_ip_addr, https, auth, result, module, timeout)

    result["diff_attributes"] = diff_attributes
    result["current_attributes"] = resp_attributes
    result["new_attributes"] = attributes

    if len(diff_attributes) > 0:
        ret_code = to_fos_singleton(module_name, obj_name, diff_attributes, result)
        if ret_code != 0:
            exit_after_login(fos_ip_addr, https, auth, result, module, timeout)

        if not module.check_mode:
            ret_code = 0
            ret_code = singleton_patch(fos_user_name, fos_password, fos_ip_addr,
                                       module_name, obj_name,
                                       fos_version, https,
                                       auth, vfid, result, diff_attributes,
                                       ssh_hostkeymust, timeout)
            if ret_code != 0:
                exit_after_login(fos_ip_addr, https, auth, result, module, timeout)

        result["changed"] = True
    else:
        logout(fos_ip_addr, https, auth, result, timeout)
        module.exit_json(**result)

    logout(fos_ip_addr, https, auth, result, timeout)
    module.exit_json(**result)


def list_helper(module, fos_ip_addr, fos_user_name, fos_password, https, ssh_hostkeymust, throttle, vfid, module_name, list_name, entries, all_entries, result, timeout):

    if not is_full_human(entries, result):
        module.exit_json(**result)

    if all_entries == None:
        result["all_entries_default"] = all_entries
        all_entries = True

    if vfid is None:
        vfid = 128

    if entries == None:
        entries = []

    ret_code, auth, fos_version = login(fos_ip_addr,
                           fos_user_name, fos_password,
                           https, throttle, result, timeout)
    if ret_code != 0:
        module.exit_json(**result)

    ret_code, response = list_get(fos_user_name, fos_password, fos_ip_addr,
                                  module_name, list_name, fos_version,
                                  https, auth, vfid, result,
                                  ssh_hostkeymust, timeout)
    if ret_code != 0:
        exit_after_login(fos_ip_addr, https, auth, result, module, timeout)

    current_entries = response["Response"][str_to_yang(list_name)]
    if not isinstance(current_entries, list):
        if current_entries is None:
            current_entries = []
        else:
            current_entries = [current_entries]

    to_human_list(module_name, list_name, current_entries, result)

    # for switch list object only, we only support one for now
    # and allow users to not specifcy the WWN of the switch
    # thus missing key of the entry. We'll get it from the switch
    if module_name == "brocade_fibrechannel_switch" and list_name == "fibrechannel_switch":
        if len(entries) != 1:
            result["failed"] = True
            result["msg"] = "Only one entry in an array is supported"
            exit_after_login(fos_ip_addr, https, auth, result, module, timeout)

        entries[0]["name"] = current_entries[0]["name"]

    if module_name == "brocade_access_gateway" and list_name == "port_group":
        for port_group in current_entries:
            if "port_group_n_ports" in port_group and port_group["port_group_n_ports"] == None:
                port_group["port_group_n_ports"] = {"n_port": None}
            if "port_group_f_ports" in port_group and port_group["port_group_f_ports"] == None:
                port_group["port_group_f_ports"] = {"f_port": None}

    diff_entries = []
    for entry in entries:
        for current_entry in current_entries:
            if list_entry_keys_matched(entry, current_entry, module_name, list_name):
                diff_attributes = generate_diff(result, current_entry, entry)
                if len(diff_attributes) > 0:
                    for key in list_entry_keys(module_name, list_name):
                        diff_attributes[key] = entry[key]
                    diff_entries.append(diff_attributes)

    if module_name == "brocade_security" and list_name == "user_config":
        new_diff_entries = []
        for diff_entry in diff_entries:
            # password canot change using patch update
            # any entries with password are popp'ed off.
            if not "password" in diff_entry:
                new_diff_entries.append(diff_entry)
        diff_entries = new_diff_entries

    ret_code = to_fos_list(module_name, list_name, diff_entries, result)
    result["diff_retcode"] = ret_code
    if ret_code != 0:
        exit_after_login(fos_ip_addr, https, auth, result, module, timeout)

    add_entries = []
    for entry in entries:

        # check to see if the new entry matches any of the old ones
        found = False
        for current_entry in current_entries:
            if list_entry_keys_matched(entry, current_entry, module_name, list_name):
                found = True
                break

        if not found:
            new_entry = {}
            for k, v in entry.items():
                new_entry[k] = v
            add_entries.append(new_entry)

    if module_name == "brocade_logging" and list_name == "syslog_server":
        new_add_entries = []
        for add_entry in add_entries:
            secured = ("secured_mode" in add_entry and add_entry["secured_mode"] == True)
            if not secured:
                new_add_entry = {}
                new_add_entry["server"] = add_entry["server"]
                new_add_entries.append(new_add_entry)
            else:
                new_add_entries.append(add_entry)
        add_entries = new_add_entries

    ret_code = to_fos_list(module_name, list_name, add_entries, result)
    result["add_retcode"] = ret_code
    if ret_code != 0:
        exit_after_login(fos_ip_addr, https, auth, result, module, timeout)

    delete_entries = []
    for current_entry in current_entries:
        found = False
        for entry in entries:
            if list_entry_keys_matched(entry, current_entry, module_name, list_name):
                found = True
                break

        if not found:
            delete_entry = {}
            for key in list_entry_keys(module_name, list_name):
                delete_entry[key] = current_entry[key]

            delete_entries.append(delete_entry)

    ret_code = to_fos_list(module_name, list_name, delete_entries, result)
    result["delete_retcode"] = ret_code
    if ret_code != 0:
        exit_after_login(fos_ip_addr, https, auth, result, module, timeout)

    result["response"] = response
    result["current_entries"] = current_entries
    result["diff_entries"] = diff_entries
    result["add_entries"] = add_entries
    result["delete_entries"] = delete_entries

    if len(diff_entries) > 0:
        if not module.check_mode:
            ret_code = 0
            ret_code = list_patch(fos_user_name, fos_password, fos_ip_addr, module_name, list_name, fos_version, https, auth, vfid, result, diff_entries, ssh_hostkeymust, timeout)
            if ret_code != 0:
                exit_after_login(fos_ip_addr, https, auth, result, module, timeout)

        result["changed"] = True

    if len(add_entries) > 0:
        if not module.check_mode:
            ret_code = list_post(fos_user_name, fos_password, fos_ip_addr, module_name, list_name, fos_version, https, auth, vfid, result, add_entries, ssh_hostkeymust, timeout)
            if ret_code != 0:
                exit_after_login(fos_ip_addr, https, auth, result, module, timeout)

        result["changed"] = True

    if len(delete_entries) > 0 and all_entries:
        if not module.check_mode:
            ret_code = list_delete(fos_user_name, fos_password, fos_ip_addr, module_name, list_name, fos_version, https, auth, vfid, result, delete_entries, ssh_hostkeymust, timeout)
            if ret_code != 0:
                exit_after_login(fos_ip_addr, https, auth, result, module, timeout)

        result["changed"] = True

    logout(fos_ip_addr, https, auth, result, timeout)
    module.exit_json(**result)

def list_delete_helper(module, fos_ip_addr, fos_user_name, fos_password, https, ssh_hostkeymust, throttle, vfid, module_name, list_name, entries, all_entries, result, timeout):

    if not is_full_human(entries, result):
        module.exit_json(**result)

    if all_entries == None:
        result["all_entries_default"] = all_entries
        all_entries = True

    if vfid is None:
        vfid = 128

    ret_code, auth, fos_version = login(fos_ip_addr,
                           fos_user_name, fos_password,
                           https, throttle, result, timeout)
    if ret_code != 0:
        module.exit_json(**result)

    ret_code, response = list_get(fos_user_name, fos_password, fos_ip_addr,
                                  module_name, list_name, fos_version,
                                  https, auth, vfid, result,
                                  ssh_hostkeymust, timeout)
    if ret_code != 0:
        exit_after_login(fos_ip_addr, https, auth, result, module, timeout)

    current_entries = response["Response"][str_to_yang(list_name)]
    if not isinstance(current_entries, list):
        if current_entries is None:
            current_entries = []
        else:
            current_entries = [current_entries]

    to_human_list(module_name, list_name, current_entries, result)

    delete_entries = []
    for entry in entries:

        # check to see if the new entry matches any of the old ones
        found = False
        for current_entry in current_entries:
            if list_entry_keys_matched(entry, current_entry, module_name, list_name):
                found = True
                break

        if found:
            new_entry = {}
            for k, v in entry.items():
                new_entry[k] = v
            delete_entries.append(new_entry)

    ret_code = to_fos_list(module_name, list_name, delete_entries, result)
    result["add_retcode"] = ret_code
    if ret_code != 0:
        exit_after_login(fos_ip_addr, https, auth, result, module, timeout)

    result["response"] = response
    result["current_entries"] = current_entries
    result["delete_entries"] = delete_entries

    if len(delete_entries) > 0:
        if not module.check_mode:
            ret_code = list_delete(fos_user_name, fos_password, fos_ip_addr, module_name, list_name, fos_version, https, auth, vfid, result, delete_entries, ssh_hostkeymust, timeout)
            if ret_code != 0:
                exit_after_login(fos_ip_addr, https, auth, result, module, timeout)

        result["changed"] = True

    logout(fos_ip_addr, https, auth, result, timeout)
    module.exit_json(**result)


def operation_helper(module, fos_ip_addr, fos_user_name, fos_password, https, ssh_hostkeymust, throttle, vfid, op_name, in_name, attributes, result, timeout):

    if not is_full_human(attributes, result):
        module.exit_json(**result)

    if vfid is None:
        vfid = 128

    ret_code, auth, fos_version = login(fos_ip_addr,
                           fos_user_name, fos_password,
                           https, throttle, result, timeout)
    if ret_code != 0:
        module.exit_json(**result)

    result["input"] = attributes

    ret_code = to_fos_operation(op_name, in_name, attributes, result)
    if ret_code != 0:
        exit_after_login(fos_ip_addr, https, auth, result, module, timeout)

    if not module.check_mode:
        ret_code = 0
        ret_code, resp = operation_post(fos_user_name, fos_password, fos_ip_addr,
                                   op_name, in_name,
                                   fos_version, https,
                                   auth, vfid, result, attributes,
                                   ssh_hostkeymust, timeout)
        if ret_code != 0:
            exit_after_login(fos_ip_addr, https, auth, result, module, timeout)

    result["changed"] = True

    to_human_operation(op_name, in_name, resp["Response"])

    result["operation_resp"] = resp["Response"]

    logout(fos_ip_addr, https, auth, result, timeout)

    module.exit_json(**result)


def operation_xml_str(result, obj_name, attributes):
    obj_name_yang = str_to_yang(obj_name)
    xml_str = ""

    xml_str = xml_str + "<" + obj_name_yang + ">"

    for k, v in attributes.items():
        xml_str = xml_str + "<" + k + ">"

        if isinstance(v, dict):
            for k1, v1 in v.items():
                if isinstance(v1, list):
                    for entry in v1:
                        xml_str = xml_str + "<" + k1 + ">" + str(entry) + "</" + k1 + ">"
                else:
                    xml_str = xml_str + "<" + k1 + ">" + str(v1) + "</" + k1 + ">"
        else:
            xml_str = xml_str + str(v)

        xml_str = xml_str + "</" + k + ">"

    xml_str = xml_str + "</" + obj_name_yang + ">"

    return xml_str


def operation_post(login, password, fos_ip_addr, op_name, in_name, fos_version, is_https, auth, vfid, result, attributes, ssh_hostkeymust, timeout):
    """
        update existing user config configurations

        :param fos_ip_addr: ip address of FOS switch
        :type fos_ip_addr: str
        :param is_https: indicate to use HTTP or HTTPS
        :type is_https: bool
        :param auth: authorization struct from login
        :type struct: dict
        :param result: dict to keep track of execution msgs
        :type result: dict
        :param diff_attributes: list of attributes for update
        :type ports: dict
        :return: code to indicate failure or success
        :rtype: int
        :return: list of dict of chassis configurations
        :rtype: list
    """
    full_url, validate_certs = full_url_get(is_https,
                                            fos_ip_addr,
                                            OP_PREFIX + op_name)

    xml_str = operation_xml_str(result, in_name, attributes)

    result["post_url"] = full_url
    result["post_str"] = xml_str

    return url_post_resp(fos_ip_addr, is_https, auth, vfid, result,
                         full_url, xml_str, timeout)


def to_fos_operation(op_name, in_name, attributes, result):
    human_to_yang(attributes)

    for k, v in attributes.items():
        # if going to fos, we need to encode password
        if op_name == "supportsave" and in_name == "connection":
            if k == "password":
                attributes[k] = base64.b64encode(attributes[k].encode('ascii')).decode('utf-8')
        if op_name == "firmwaredownload" and in_name == "firmwaredownload_parameters":
            if k == "password":
                attributes[k] = base64.b64encode(attributes[k].encode('ascii')).decode('utf-8')

    for k, v in attributes.items():
        if isinstance(v, bool):
            if v == True:
                attributes[k] = "true"
            else:
                attributes[k] = "false"

    return 0


def to_human_operation(op_name, in_name, attributes):
    yang_to_human(attributes)

    for k, v in attributes.items():
        if v == "true":
            attributes[k] = True
        elif v == "false":
            attributes[k] = False
