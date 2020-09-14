# Copyright 2019 Broadcom. All rights reserved.
# The term 'Broadcom' refers to Broadcom Inc. and/or its subsidiaries.
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import (absolute_import, division, print_function)
from ansible.module_utils.brocade_ssh import ssh_and_configure

__metaclass__ = type


"""
Brocade logging utils
"""


def v1_trap_patch(login, password, fos_ip_addr, fos_version, is_https, auth,
                       vfid, result, v1_traps, ssh_hostkeymust, timeout):
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
    l_v1_traps = v1_traps[:]

    if fos_version < "v9.0":
        for l_v1_trap in l_v1_traps:
            if "host" in l_v1_trap and l_v1_trap["host"] == "0.0.0.0":
                rssh, sshstr = ssh_and_configure(login, password, fos_ip_addr, ssh_hostkeymust, "snmpconfig --set snmpv1 -index " + str(l_v1_trap["index"]) + " -host 0.0.0.0" , "Committing configuration.....done.")
                if rssh != 0:
                    result["failed"] = True
                    result["msg"] = "Failed to reset host IP to 0.0.0.0. " + sshstr
                else:
                    result["changed"] = True
                    result["messages"] = "IP is reset to 0.0.0.0"

                l_v1_trap.pop("host")

    rest_v1_traps = []

    for l_v1_trap in l_v1_traps:
        if len(l_v1_trap) > 1:
            rest_v1_traps.append(l_v1_trap)

    return rest_v1_traps


def v3_trap_patch(login, password, fos_ip_addr, fos_version, is_https, auth,
                       vfid, result, v3_traps, ssh_hostkeymust, timeout):
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
    l_v3_traps = v3_traps[:]

    if fos_version < "v9.0":
        for l_v3_trap in l_v3_traps:
            if "host" in l_v3_trap and l_v3_trap["host"] == "0.0.0.0":
                rssh, sshstr = ssh_and_configure(login, password, fos_ip_addr, ssh_hostkeymust, "snmpconfig --set snmpv3 -index " + str(l_v3_trap["trap-index"]) + " -host 0.0.0.0" , "Committing configuration.....done.")
                if rssh != 0:
                    result["failed"] = True
                    result["msg"] = "Failed to reset host IP to 0.0.0.0. " + sshstr
                else:
                    result["changed"] = True
                    result["messages"] = "IP is reset to 0.0.0.0"

                l_v3_trap.pop("host")

    rest_v3_traps = []

    for l_v3_trap in l_v3_traps:
        if len(l_v3_trap) > 1:
            rest_v3_traps.append(l_v3_trap)

    return rest_v3_traps
