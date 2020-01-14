# Copyright 2019 Broadcom. All rights reserved.
# The term 'Broadcom' refers to Broadcom Inc. and/or its subsidiaries.
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import (absolute_import, division, print_function)
from ansible.module_utils.brocade_url import url_get_to_dict, url_patch, full_url_get, url_patch_single_object
from ansible.module_utils.brocade_yang import yang_to_human, human_to_yang

__metaclass__ = type


"""
Brocade Fibre Channel snmp utils
"""


REST_SNMP_SYSTEM = "/rest/running/brocade-snmp/system"


def to_human_system(system_config):
    for k, v in system_config.items():
        if v == "true":
            system_config[k] = True
        elif v == "false":
            system_config[k] = False

    yang_to_human(system_config)

def to_fos_system(system_config, result):
    human_to_yang(system_config)

    for k, v in system_config.items():
        if isinstance(v, bool):
            if v == True:
                system_config[k] = "true"
            else:
                system_config[k] = "false"

    return 0


def system_get(login, password, fos_ip_addr, fos_version, is_https, auth, vfid, result):
    """
        retrieve existing snmp system configurations

        :param fos_ip_addr: ip address of FOS switch
        :type fos_ip_addr: str
        :param is_https: indicate to use HTTP or HTTPS
        :type is_https: bool
        :param auth: authorization struct from login
        :type auth: dict
        :param result: dict to keep track of execution msgs
        :type result: dict
        :return: code to indicate failure or success
        :rtype: int
        :return: dict of switch configurations
        :rtype: dict
    """
    full_url, validate_certs = full_url_get(is_https,
                                            fos_ip_addr,
                                            REST_SNMP_SYSTEM)

    rtype, rdict = url_get_to_dict(fos_ip_addr, is_https, auth, vfid,
                           result, full_url)

    if rtype != 0:
        result["failed"] = True
        result["msg"] = "API failed to return data"
        return -1, None

    return 0, rdict

def system_patch(login, password, fos_ip_addr, fos_version, is_https, auth,
                    vfid, result, diff_attributes):
    """
        update existing switch configurations

        :param fos_ip_addr: ip address of FOS switch
        :type fos_ip_addr: str
        :param is_https: indicate to use HTTP or HTTPS
        :type is_https: bool
        :param auth: authorization struct from login
        :type auth: dict
        :param result: dict to keep track of execution msgs
        :type result: dict
        :param diff_attributes: list of attributes for update
        :type ports: dict
        :return: code to indicate failure or success
        :rtype: int
        :return: dict of switch configurations
        :rtype: dict
    """
    l_diffs = diff_attributes.copy()

    full_url, validate_certs = full_url_get(is_https,
                                            fos_ip_addr,
                                            REST_SNMP_SYSTEM)

    return (url_patch_single_object(fos_ip_addr, is_https, auth,
                                    vfid, result, full_url,
                                    "system", l_diffs))
