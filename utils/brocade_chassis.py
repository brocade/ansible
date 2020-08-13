# Copyright 2019 Broadcom. All rights reserved.
# The term 'Broadcom' refers to Broadcom Inc. and/or its subsidiaries.
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import (absolute_import, division, print_function)
from ansible.module_utils.brocade_url import url_get_to_dict, url_patch, full_url_get, url_patch_single_object
from ansible.module_utils.brocade_ssh import ssh_and_configure
from ansible.module_utils.brocade_yang import yang_to_human, human_to_yang

__metaclass__ = type


"""
Brocade chassis utils
"""


REST_CHASSIS = "/rest/running/brocade-chassis/chassis"


def chassis_get(login, password, fos_ip_addr, fos_version, is_https, auth, vfid, result, ssh_hostkeymust, timeout):
    """
        retrieve existing switch configurations

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
        :return: dict of chassis configurations
        :rtype: dict
    """
    full_chassis_url, validate_certs = full_url_get(is_https,
                                                    fos_ip_addr,
                                                    REST_CHASSIS)

    rtype, rdict = url_get_to_dict(fos_ip_addr, is_https, auth, vfid,
                           result, full_chassis_url, timeout)
    if rtype != 0:
        result["failed"] = True
        result["msg"] = "API failed to return data"
        return -1, None

    rssh, sshstr = ssh_and_configure(login, password, fos_ip_addr, ssh_hostkeymust, "timeout", "showcommand")
    if rssh == 0:
        if "Current IDLE Timeout is " in sshstr:
            text = sshstr[len("Current IDLE Timeout is "):]
            timeout = text.split(" ")
            rdict["Response"]["chassis"]["telnet-timeout"] = timeout[0]
        elif "Shell Idle Timeout is " in sshstr:
            text = sshstr[len("Shell Idle Timeout is "):]
            timeout = text.split(" ")
            rdict["Response"]["chassis"]["telnet-timeout"] = timeout[0]
        else:
            result["failed"] = True
            result["msg"] = "telnet_timeout returned unknown string"
            return -1, None

    return 0, rdict


def chassis_patch(login, password, fos_ip_addr, fos_version, is_https, auth, vfid, result, diff_attributes, ssh_hostkeymust, timeout):
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
        :return: list of dict of chassis configurations
        :rtype: list
    """
    l_diffs = diff_attributes.copy()

    if "telnet-timeout" in l_diffs:
        rssh, sshstr = ssh_and_configure(login, password, fos_ip_addr, ssh_hostkeymust, "timeout " + str(l_diffs["telnet-timeout"]), "Timeout will be in effect after NEXT login")
        if rssh != 0:
            result["failed"] = True
            result["msg"] = "Failed to set telnet-timeout. " + sshstr
        else:
            result["changed"] = True
            result["messages"] = "telnet-timeout set"
        l_diffs.pop("telnet-timeout")

    if len(l_diffs) == 0:
        return 0

    full_chassis_url, validate_certs = full_url_get(is_https,
                                                    fos_ip_addr,
                                                    REST_CHASSIS)

    return (url_patch_single_object(fos_ip_addr, is_https, auth,
                                    vfid, result, full_chassis_url,
                                    "chassis", l_diffs, timeout))
