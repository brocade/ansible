# Copyright 2019 Broadcom. All rights reserved.
# The term 'Broadcom' refers to Broadcom Inc. and/or its subsidiaries.
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import (absolute_import, division, print_function)
from ansible.module_utils.brocade_url import url_get_to_dict, url_patch, full_url_get, url_patch_single_object, url_post, url_delete
from ansible.module_utils.brocade_yang import yang_to_human, human_to_yang
from ansible.module_utils.brocade_ssh import ssh_and_configure
import base64

__metaclass__ = type


"""
Brocade logging utils
"""


REST_PREFIX = "/rest/running/"


def to_human_singleton(module_name, obj_name, attributes):
    for k, v in attributes.items():
        if v == "true":
            attributes[k] = True
        elif v == "false":
            attributes[k] = False

    yang_to_human(attributes)


def to_fos_singleton(module_name, obj_name, attributes, result):
    human_to_yang(attributes)

    for k, v in attributes.items():
        if isinstance(v, bool):
            if v == True:
                attributes[k] = "true"
            else:
                attributes[k] = "false"
        # if going to fos, we need to encode password
        if module_name == "brocade-security" and obj_name == "password" and k == "old-password":
            attributes[k] = base64.b64encode(attributes[k].encode('ascii')).decode('utf-8')
        if module_name == "brocade-security" and obj_name == "password" and k == "new-password":
            attributes[k] = base64.b64encode(attributes[k].encode('ascii')).decode('utf-8')

    return 0


def singleton_get(login, password, fos_ip_addr, module_name, obj_name, fos_version, is_https, auth, vfid, result, ssh_hostkeymust):
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
    full_url, validate_certs = full_url_get(is_https,
                                            fos_ip_addr,
                                            REST_PREFIX + module_name + "/" + obj_name)

    ret, resp = url_get_to_dict(fos_ip_addr, is_https, auth, vfid,
                                result, full_url)

    if ret == -2:
        # return empty dict. GET isn't supported
        result["daniel1"] = "here"
        return 0, ({"Response" : {obj_name: {}}})

    return ret, resp


def to_human_list(module_name, list_name, attributes_list, result):
    for attributes in attributes_list:
        for k, v in attributes.items():
            if v == "true":
                attributes[k] = True
            elif v == "false":
                attributes[k] = False

            if module_name == "brocade-snmp" and list_name == "v3-account":
                if k == "authentication-password" or k == "privacy-password":
                    if str(v) != "None":
                        attributes[k] = base64.b64decode(v)

        yang_to_human(attributes)


def to_fos_list(module_name, list_name, attributes_list, result):
    for attributes in attributes_list:
        human_to_yang(attributes)

        for k, v in attributes.items():
            if isinstance(v, bool):
                if v == True:
                    attributes[k] = "true"
                else:
                    attributes[k] = "false"

            if module_name == "brocade-snmp" and list_name == "v3-account":
                if k == "authentication-password" or k == "privacy-password":
                    if str(v) != "None":
                        attributes[k] = base64.b64encode(v.encode('ascii')).decode('utf-8')

    return 0

list_keys = {
    "brocade-snmp": {
        "v1-account" : ["index"],
        "v1-trap" : ["index"],
        "v3-account" : ["index"],
        "v3-trap" : ["trap_index"],
        "access-control" : ["index"],
        "trap-capability" : ["trap_name"],
        "mib-capability" : ["mib_name"],
    }
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

def list_get(login, password, fos_ip_addr, module_name, list_name, fos_version, is_https, auth, vfid, result, ssh_hostkeymust):
    return singleton_get(login, password, fos_ip_addr, module_name, list_name, fos_version, is_https, auth, vfid, result, ssh_hostkeymust)


def singleton_xml_str(result, obj_name, attributes):
    xml_str = ""

    xml_str = xml_str + "<" + obj_name + ">"

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

    xml_str = xml_str + "</" + obj_name + ">"

    return xml_str


def singleton_patch(login, password, fos_ip_addr, module_name, obj_name, fos_version, is_https, auth, vfid, result, new_attributes, ssh_hostkeymust):
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
                                            REST_PREFIX + module_name + "/" + obj_name)

    xml_str = singleton_xml_str(result, obj_name, new_attributes)

    result["patch_obj_str"] = xml_str

    return url_patch(fos_ip_addr, is_https, auth, vfid, result,
                     full_url, xml_str)


def list_xml_str(result, module_name, list_name, entries):
    xml_str = ""

    for entry in entries:
        xml_str = xml_str + "<" + list_name + ">"

        # add the key entries first
        for k, v in entry.items():
            if k in list_entry_keys(module_name, list_name):
                xml_str = xml_str + "<" + k + ">" + str(v) + "</" + k + ">"

        # add non key entries next
        for k, v in entry.items():
            if k not in list_entry_keys(module_name, list_name):
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

        xml_str = xml_str + "</" + list_name + ">"

    return xml_str


def list_patch(login, password, fos_ip_addr, module_name, list_name, fos_version, is_https, auth, vfid, result, entries, ssh_hostkeymust):
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

    result["patch_str"] = xml_str

    return url_patch(fos_ip_addr, is_https, auth, vfid, result,
                     full_url, xml_str)


def list_post(login, password, fos_ip_addr, module_name, list_name, fos_version, is_https, auth, vfid, result, entries, ssh_hostkeymust):
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
                     full_url, xml_str)


def list_delete(login, password, fos_ip_addr, module_name, list_name, fos_version, is_https, auth, vfid, result, entries, ssh_hostkeymust):
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
                     full_url, xml_str)
