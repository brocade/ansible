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
Brocade Fibre Channel switch utils
"""


REST_SWITCH = "/rest/running/brocade-fibrechannel-switch/fibrechannel-switch"


def to_human_switch(switch_config):
    # convert all boolean strings to boolean
    # first. Then convert integer booleans
    # to boolean
    yang_to_human(switch_config)

    for k, v in switch_config.items():
        if v == "true":
            switch_config[k] = True
        elif v == "false":
            switch_config[k] = False

    if "enabled_state" in switch_config:
        if switch_config["enabled_state"] == "3":
            switch_config["enabled_state"] = False
        else:
            switch_config["enabled_state"] = True


def to_fos_switch(switch_config, result):
    human_to_yang(switch_config)

    if "enabled-state" in switch_config:
        if isinstance(switch_config["enabled-state"], bool):
            if switch_config["enabled-state"] == False:
                switch_config["enabled-state"] = "3"
            else:
                switch_config["enabled-state"] = "2"
        else:
            result["failed"] = True
            result["msg"] = "enabled-state converted to unknown"
            return -1

    # convert the boolean to integers first
    # then convert the rest of the booleans to bool string
    for k, v in switch_config.items():
        if isinstance(v, bool):
            if v == True:
                switch_config[k] = "true"
            else:
                switch_config[k] = "false"

    return 0


def fc_switch_get(login, password, fos_ip_addr, fos_version, is_https, auth, vfid, result, ssh_hostkeymust, timeout):
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
        :return: dict of switch configurations
        :rtype: dict
    """
    full_fc_switch_url, validate_certs = full_url_get(is_https,
                                                      fos_ip_addr,
                                                      REST_SWITCH)

    rtype, rdict = url_get_to_dict(fos_ip_addr, is_https, auth, vfid,
                           result, full_fc_switch_url, timeout)

    if rtype != 0:
        result["failed"] = True
        result["msg"] = "API failed to return data"
        return -1, None

    result["fos_version"] = fos_version
    result["fos_version_check"] = fos_version < "v9.0"
    if fos_version < "v9.0":
        rssh, sshstr = ssh_and_configure(login, password, fos_ip_addr, ssh_hostkeymust, "dlsshow", "showcommand")
        if rssh == 0:
            if "DLS is set with Lossless disabled" in sshstr or "Error: This command is not supported in AG mode" in sshstr:
                rdict["Response"]["fibrechannel-switch"]["dynamic-load-sharing"] = "disabled"
            elif "DLS is set with Lossless enabled, Two-hop Lossless disabled" in sshstr:
                rdict["Response"]["fibrechannel-switch"]["dynamic-load-sharing"] = "lossless-dls"
            elif "DLS is set with Two-hop Lossless enabled" in sshstr:
                rdict["Response"]["fibrechannel-switch"]["dynamic-load-sharing"] = "two-hop-lossless-dls"
            else:
                result["failed"] = True
                result["msg"] = "DLS returned unknown string"
                return -1, None

    return 0, rdict


def fc_switch_patch(login, password, fos_ip_addr, fos_version, is_https, auth,
                    vfid, result, diff_attributes, ssh_hostkeymust, timeout):
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

    if fos_version < "v9.0":
        if "dynamic-load-sharing" in l_diffs:
            if l_diffs["dynamic-load-sharing"] == "disabled":
                rssh, sshstr = ssh_and_configure(login, password, fos_ip_addr, ssh_hostkeymust, "dlsset --disable -lossless", "Lossless is not set")
                if rssh != 0:
                    result["failed"] = True
                    result["msg"] = "Failed to disable DLS lossless. " + sshstr
                else:
                    rssh, sshstr = ssh_and_configure(login, password, fos_ip_addr, ssh_hostkeymust, "dlsset --disable -twohop", "Two-hop lossless is not set")
                    if rssh != 0:
                        result["failed"] = True
                        result["msg"] = "Failed to disable DLS twohop. " + sshstr
                    else:
                        result["changed"] = True
            elif l_diffs["dynamic-load-sharing"] == "lossless-dls":
                rssh, sshstr = ssh_and_configure(login, password, fos_ip_addr, ssh_hostkeymust, "dlsset --enable -lossless", "Lossless is set")
                if rssh != 0:
                    result["failed"] = True
                    result["msg"] = "Failed to enable DLS lossless. " + sshstr
                else:
                    rssh, sshstr = ssh_and_configure(login, password, fos_ip_addr, ssh_hostkeymust, "dlsset --disable -twohop", ["Two-hop lossless disabled successfully", "Two-hop lossless is not set"])
                    if rssh != 0:
                        result["failed"] = True
                        result["msg"] = "Failed to disable DLS twohop. " + sshstr
                    else:
                        result["changed"] = True
                        result["messages"] = "disabled DSL twohop"
            elif l_diffs["dynamic-load-sharing"] == "two-hop-lossless-dls":
                rssh, sshstr = ssh_and_configure(login, password, fos_ip_addr, ssh_hostkeymust, "dlsset --enable -lossless", "Lossless is set")
                if rssh != 0:
                    result["failed"] = True
                    result["msg"] = "Failed to enable DLS lossless. " + sshstr
                else:
                    rssh, sshstr = ssh_and_configure(login, password, fos_ip_addr, ssh_hostkeymust, "dlsset --enable -twohop", "Two-hop lossless enabled successfully")
                    if rssh != 0:
                        result["failed"] = True
                        result["msg"] = "Failed to enable DLS twohop. " + sshstr
                    else:
                        result["changed"] = True
                        result["messages"] = "enable DSL two-hop-lossless-dls"
            else:
                result["failed"] = True
                result["msg"] = "Unkown DLS mode"
            l_diffs.pop("dynamic-load-sharing")

    # should be only key for the switch if nothing else
    if len(l_diffs) <= 1:
        return 0

    full_fc_switch_url, validate_certs = full_url_get(is_https,
                                                      fos_ip_addr,
                                                      REST_SWITCH)

    return (url_patch_single_object(fos_ip_addr, is_https, auth,
                                    vfid, result, full_fc_switch_url,
                                    "fibrechannel-switch", l_diffs, timeout))
