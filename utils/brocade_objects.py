# Copyright 2019 Broadcom. All rights reserved.
# The term 'Broadcom' refers to Broadcom Inc. and/or its subsidiaries.
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import (absolute_import, division, print_function)
from ansible.module_utils.brocade_url import url_get_to_dict, url_patch, full_url_get, url_patch_single_object, url_post, url_delete
from ansible.module_utils.brocade_yang import yang_to_human, human_to_yang
from ansible.module_utils.brocade_ssh import ssh_and_configure

__metaclass__ = type


"""
Brocade logging utils
"""


REST_PREFIX = "/rest/running/"


def to_human_singleton(attributes):
    for k, v in attributes.items():
        if v == "true":
            attributes[k] = True
        elif v == "false":
            attributes[k] = False

    yang_to_human(attributes)


def to_fos_singleton(attributes, result):
    human_to_yang(attributes)

    for k, v in attributes.items():
        if isinstance(v, bool):
            if v == True:
                attributes[k] = "true"
            else:
                attributes[k] = "false"

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

    result["daniel2"] = "why"
    return ret, resp


def singleton_xml_str(result, obj_name, attributes):
    xml_str = ""

    xml_str = xml_str + "<" + obj_name + ">"

    for k, v in attributes.items():
        xml_str = xml_str + "<" + k + ">" +\
                      str(v) + "</" + k + ">"

    xml_str = xml_str + "</" + obj_name + ">"

    return xml_str


def singleton_patch(login, password, fos_ip_addr, module_name, obj_name, fos_version, is_https, auth,
                       vfid, result, new_attributes, ssh_hostkeymust):
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
