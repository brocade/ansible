# Copyright 2019 Broadcom. All rights reserved.
# The term 'Broadcom' refers to Broadcom Inc. and/or its subsidiaries.
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import (absolute_import, division, print_function)
from ansible_collections.daniel_chung_broadcom.fos.plugins.module_utils.brocade_url import url_get_to_dict, url_patch, HTTP, HTTPS
from ansible_collections.daniel_chung_broadcom.fos.plugins.module_utils.brocade_yang import yang_to_human, human_to_yang

__metaclass__ = type


"""
Brocade Fibre Channel port utils
"""


REST_FC = "/rest/running/brocade-interface/fibrechannel"
REST_FC_STATS = "/rest/running/brocade-interface/fibrechannel-statistics"


zero_one_attributes = [
    "g-port-locked",
    "e-port-disable",
    "n-port-enabled",
    "d-port-enable",
    "persistent-disable",
    "qos-enabled",
    "compression-configured",
    "encryption-enabled",
    "target-driven-zoning-enable",
    "sim-port-enabled",
    "mirror-port-enabled",
    "credit-recovery-enabled",
    "csctl-mode-enabled",
    "fault-delay-enabled",
    "vc-link-init",
    "isl-ready-mode-enabled",
    "rscn-suppression-enabled",
    "npiv-enabled",
    "npiv-flogi-logout-enabled",
    "ex-port-enabled",
    "fec-enabled",
    "via-tts-fec-enabled",
    "port-autodisable-enabled",
    "non-dfe-enabled",
    "trunk-port-enabled",
    ]


def to_human_fc(port_config):
    # convert real boolean strings to boolean first
    # then convert the non 0/1 integers to boolean
    # then convert the 0/1 integers to boolean
    for k, v in port_config.items():
        if v == "true":
            port_config[k] = True
        elif v == "false":
            port_config[k] = False

    if "enabled-state" in port_config:
        if port_config["enabled-state"] == "2":
            port_config["enabled-state"] = True
        else:
            port_config["enabled-state"] = False

    for attrib in zero_one_attributes:
        if attrib in port_config:
            if port_config[attrib] == "0":
                port_config[attrib] = False
            else:
                port_config[attrib] = True

    if "los-tov-mode-enabled" in port_config:
        if port_config["los-tov-mode-enabled"] == "0":
            port_config["los-tov-mode-enabled"] = "Disabled"
        elif port_config["los-tov-mode-enabled"] == "1":
            port_config["los-tov-mode-enabled"] = "Fixed"
        elif port_config["los-tov-mode-enabled"] == "2":
            port_config["los-tov-mode-enabled"] = "FixedAuto"

    if "long-distance" in port_config:
        if port_config["long-distance"] == "0":
            port_config["long-distance"] = "Disabled"
        elif port_config["long-distance"] == "1":
            port_config["long-distance"] = "L0"
        elif port_config["long-distance"] == "2":
            port_config["long-distance"] = "L1"
        elif port_config["long-distance"] == "3":
            port_config["long-distance"] = "L2"
        elif port_config["long-distance"] == "4":
            port_config["long-distance"] = "LE"
        elif port_config["long-distance"] == "5":
            port_config["long-distance"] = "L0.5"
        elif port_config["long-distance"] == "6":
            port_config["long-distance"] = "LD"
        elif port_config["long-distance"] == "7":
            port_config["long-distance"] = "LS"

    if "speed" in port_config:
        if port_config["speed"] == "32000000000":
            port_config["speed"] = "32Gig"
        if port_config["speed"] == "16000000000":
            port_config["speed"] = "16Gig"
        if port_config["speed"] == "10000000000":
            port_config["speed"] = "10Gig"
        if port_config["speed"] == "8000000000":
            port_config["speed"] = "8Gig"
        if port_config["speed"] == "4000000000":
            port_config["speed"] = "4Gig"
        if port_config["speed"] == "2000000000":
            port_config["speed"] = "2Gig"
        if port_config["speed"] == "1000000000":
            port_config["speed"] = "1Gig"
        if port_config["speed"] == "0":
            port_config["speed"] = "Auto"

    yang_to_human(port_config)

def to_fos_fc(port_config, result):
    human_to_yang(port_config)

    # convert boolean to non 0/1 integer
    # convert boolean to 0/1 integer
    # convert the rest to boolean string
    if "enabled-state" in port_config:
        if port_config["enabled-state"] == True:
            port_config["enabled-state"] = "2"
        elif port_config["enabled-state"] == False:
            port_config["enabled-state"] = "6"
        else:
            result["failed"] = True
            result["msg"] = "enabled-state converted to unknown value"
            return -1

    for attrib in zero_one_attributes:
        if attrib in port_config:
            if isinstance(port_config[attrib], bool):
                if port_config[attrib] == False:
                    port_config[attrib] = "0"
                else:
                    port_config[attrib] = "1"
            else:
                result["failed"] = True
                result["msg"] = attrib + " converted non-bool value"
                return -1

    for k, v in port_config.items():
        if isinstance(v, bool):
            if v == True:
                port_config[k] = "true"
            else:
                port_config[k] = "false"

    if "los-tov-mode-enabled" in port_config:
        if port_config["los-tov-mode-enabled"] == "Disabled":
            port_config["los-tov-mode-enabled"] = "0"
        elif port_config["los-tov-mode-enabled"] == "Fixed":
            port_config["los-tov-mode-enabled"] = "1"
        elif port_config["los-tov-mode-enabled"] == "FixedAuto":
            port_config["los-tov-mode-enabled"] = "2"
        else:
            result["failed"] = True
            result["msg"] = "los-tov-mode-enabled converted to unknown value"
            return -1

    if "long-distance" in port_config:
        if port_config["long-distance"] == "Disabled":
            port_config["long-distance"] = "0"
        elif port_config["long-distance"] == "L0":
            port_config["long-distance"] = "1"
        elif port_config["long-distance"] == "L1":
            port_config["long-distance"] = "2"
        elif port_config["long-distance"] == "L2":
            port_config["long-distance"] = "3"
        elif port_config["long-distance"] == "LE":
            port_config["long-distance"] = "4"
        elif port_config["long-distance"] == "L0.5":
            port_config["long-distance"] = "5"
        elif port_config["long-distance"] == "LD":
            port_config["long-distance"] = "6"
        elif port_config["long-distance"] == "LS":
            port_config["long-distance"] = "7"
        else:
            result["failed"] = True
            result["msg"] = "long-distance converted to unknown value"
            return -1

    if "speed" in port_config:
        if port_config["speed"] == "32Gig":
            port_config["speed"] = "32000000000"
        if port_config["speed"] == "16Gig":
            port_config["speed"] = "16000000000"
        if port_config["speed"] == "8Gig":
            port_config["speed"] = "10000000000"
        if port_config["speed"] == "10Gig":
            port_config["speed"] = "8000000000"
        if port_config["speed"] == "4Gig":
            port_config["speed"] = "4000000000"
        if port_config["speed"] == "2Gig":
            port_config["speed"] = "2000000000"
        if port_config["speed"] == "1Gig":
            port_config["speed"] = "1000000000"
        if port_config["speed"] == "Auto":
            port_config["speed"] = "0"
        else:
            result["failed"] = True
            result["msg"] = "speed converted to unknown value"
            return -1

    return 0


def fc_port_get(fos_ip_addr, is_https, auth, vfid, result):
    """
        retrieve existing port configurations

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
        :return: list of dict of port configurations
        :rtype: list
    """
    full_fc_port_url = (HTTPS if is_https else HTTP) + fos_ip_addr + REST_FC

    return url_get_to_dict(fos_ip_addr, is_https, auth, vfid,
                           result, full_fc_port_url)


def fc_port_patch(fos_ip_addr, is_https, auth, vfid, result, ports):
    """
        update existing port configurations

        :param fos_ip_addr: ip address of FOS switch
        :type fos_ip_addr: str
        :param is_https: indicate to use HTTP or HTTPS
        :type is_https: bool
        :param auth: authorization struct from login
        :type auth: dict
        :param result: dict to keep track of execution msgs
        :type result: dict
        :param ports: list of ports and associated attributes for update
        :type ports: list
        :return: code to indicate failure or success
        :rtype: int
        :return: list of dict of port configurations
        :rtype: list
    """
    full_fc_port_url = (HTTPS if is_https else HTTP) + fos_ip_addr + REST_FC

    fc_port_str = ""

    for port in ports:
        fc_port_str = fc_port_str + "<fibrechannel>"

        fc_port_str = fc_port_str + "<name>" + port["name"] + "</name>"

        for k, v in port.items():
            if k != "name":
                k = k.replace("_", "-")
                fc_port_str = fc_port_str + "<" + k + ">" +\
                    str(v) + "</" + k + ">"

        fc_port_str = fc_port_str + "</fibrechannel>"

    result["fc_port_str"] = fc_port_str

    return url_patch(fos_ip_addr, is_https, auth, vfid, result,
                     full_fc_port_url, fc_port_str)


def fc_port_stats_get(fos_ip_addr, is_https, auth, vfid, result):
    """
        retrieve existing port stats

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
        :return: list of dict of port stats
        :rtype: list
    """
    full_fc_port_url = (HTTPS if is_https else HTTP) +\
        fos_ip_addr + REST_FC_STATS

    return url_get_to_dict(fos_ip_addr, is_https, auth, vfid,
                           result, full_fc_port_url)
