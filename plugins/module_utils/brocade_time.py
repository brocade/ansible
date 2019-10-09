# Copyright 2019 Broadcom. All rights reserved.
# The term 'Broadcom' refers to Broadcom Inc. and/or its subsidiaries.
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import (absolute_import, division, print_function)
from ansible.module_utils.brocade_url import url_get_to_dict, url_patch, HTTP, HTTPS, url_patch_single_object
from ansible.module_utils.brocade_yang import yang_to_human, human_to_yang

__metaclass__ = type


"""
Brocade time utils
"""


REST_CLOCK_SERVER = "/rest/running/brocade-time/clock-server"
REST_TIME_ZONE = "/rest/running/brocade-time/time-zone"


def to_human_clock_server(attributes):
    for k, v in attributes.items():
        if v == "true":
            attributes[k] = True
        elif v == "false":
            attributes[k] = False

    yang_to_human(attributes)

def to_fos_clock_server(attributes, result):
    human_to_yang(attributes)

    for k, v in attributes.items():
        if isinstance(v, bool):
            if v == True:
                attributes[k] = "true"
            else:
                attributes[k] = "false"

    return 0


def clock_server_get(fos_ip_addr, is_https, auth, vfid, result):
    """
        retrieve existing clock-server configurations

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
        :return: dict of clock server configurations
        :rtype: dict
    """
    full_cs_url = (HTTPS if is_https else HTTP) +\
        fos_ip_addr + REST_CLOCK_SERVER

    return url_get_to_dict(fos_ip_addr, is_https, auth, vfid,
                           result, full_cs_url)


def clock_server_patch(fos_ip_addr, is_https, auth,
                       vfid, result, diff_attributes):
    """
        update existing clock-server configurations

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
    full_cs_url = (HTTPS if is_https else HTTP) +\
        fos_ip_addr + REST_CLOCK_SERVER

    return (url_patch_single_object(fos_ip_addr, is_https, auth,
                                    vfid, result, full_cs_url,
                                    "clock-server", diff_attributes, longer_timeout = 300))


def to_human_time_zone(attributes):
    for k, v in attributes.items():
        if v == "true":
            attributes[k] = True
        elif v == "false":
            attributes[k] = False

    yang_to_human(attributes)

def to_fos_time_zone(attributes, result):
    human_to_yang(attributes)

    for k, v in attributes.items():
        if isinstance(v, bool):
            if v == True:
                attributes[k] = "true"
            else:
                attributes[k] = "false"

    return 0


def time_zone_get(fos_ip_addr, is_https, auth, vfid, result):
    """
        retrieve existing time-zone configurations

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
        :return: dict of clock server configurations
        :rtype: dict
    """
    full_cs_url = (HTTPS if is_https else HTTP) +\
        fos_ip_addr + REST_TIME_ZONE

    return url_get_to_dict(fos_ip_addr, is_https, auth, vfid,
                           result, full_cs_url)


def time_zone_patch(fos_ip_addr, is_https, auth,
                       vfid, result, diff_attributes):
    """
        update existing switch configurations

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
    full_cs_url = (HTTPS if is_https else HTTP) +\
        fos_ip_addr + REST_TIME_ZONE

    return (url_patch_single_object(fos_ip_addr, is_https, auth,
                                    vfid, result, full_cs_url,
                                    "time-zone", diff_attributes))
