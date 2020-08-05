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
Brocade configuration utils
"""


REST_FABRIC = "/rest/running//brocade-fibrechannel-configuration/fabric"
REST_PORT_CONFIGURATION = "/rest/running//brocade-fibrechannel-configuration/port-configuration"


def fabric_principal(login, password, fos_ip_addr, ssh_hostkeymust):
    enabled_err = None
    enabled = False
    priority_err = None
    priority = ""

    rssh, sshstr = ssh_and_configure(login, password, fos_ip_addr, ssh_hostkeymust, "fabricprincipal", "showcommand")
    if rssh == 0:
        if "Principal Selection Mode: Enable" in sshstr:
            enabled = True
        elif "Principal Selection Mode: Disable" in sshstr:
            enabled = False
        else:
            enabled_err = "fabric-principal-enabed returned unknown string"

        if "Principal Switch Selection Priority: " in sshstr:
            line = sshstr[sshstr.find("Principal Switch Selection Priority: "):]
            priority_str = line[len("Principal Switch Selection Priority: "):]
            priority = priority_str.rstrip()
        else:
            priority_err = "fabric-principal-priority returned unknown string"

    return enabled_err, enabled, priority_err, priority


def fabric_get(login, password, fos_ip_addr, fos_version, is_https, auth, vfid, result, ssh_hostkeymust, timeout):
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
        :return: dict of fabric configurations
        :rtype: dict
    """
    full_fabric_url, validate_certs = full_url_get(is_https,
                                                   fos_ip_addr,
                                                   REST_FABRIC)

    rtype, rdict = url_get_to_dict(fos_ip_addr, is_https, auth, vfid,
                                   result, full_fabric_url, timeout)
    if rtype != 0:
        result["failed"] = True
        result["msg"] = "API failed to return data"
        return -1, None

    rssh, sshstr = ssh_and_configure(login, password, fos_ip_addr, ssh_hostkeymust, "iodshow", "showcommand")
    if rssh == 0:
        if "IOD is not set" in sshstr:
            rdict["Response"]["fabric"]["in-order-delivery-enabled"] = "false"
        elif "IOD is set" in sshstr:
            rdict["Response"]["fabric"]["in-order-delivery-enabled"] = "true"
        else:
            result["failed"] = True
            result["msg"] = "IOD returned unknown string. " + sshstr
            return -1, None

    enabled_err, enabled, priority_err, priority = fabric_principal(login, password, fos_ip_addr, ssh_hostkeymust)
    if enabled_err == None:
        if enabled:
            rdict["Response"]["fabric"]["fabric-principal-enabled"] = "true"
        else:
            rdict["Response"]["fabric"]["fabric-principal-enabled"] = "false"
    else:
        result["failed"] = True
        result["msg"] = enabled_err
        return -1, None

    if priority_err == None:
        rdict["Response"]["fabric"]["fabric-principal-priority"] = priority
    else:
        result["failed"] = True
        result["msg"] = priority_err
        return -1, None

    return 0, rdict


def fabric_patch(login, password, fos_ip_addr, fos_version, is_https, auth, vfid, result, diff_attributes, ssh_hostkeymust, timeout):
    """
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
        :return: dict of fabric configurations
        :rtype: dict
    """
    l_diffs = diff_attributes.copy()

    if "in-order-delivery-enabled" in l_diffs:
        if l_diffs["in-order-delivery-enabled"] == "true":
            rssh, sshstr = ssh_and_configure(login, password, fos_ip_addr, ssh_hostkeymust, "iodset", "IOD is set")
            if rssh != 0:
                result["failed"] = True
                result["msg"] = "Failed to set IOD. " + sshstr
            else:
                result["changed"] = True
                result["messages"] = "in-order-delivery-enabled set"
        elif l_diffs["in-order-delivery-enabled"] == "false":
            rssh, sshstr = ssh_and_configure(login, password, fos_ip_addr, ssh_hostkeymust, "iodreset", "IOD is not set")
            if rssh != 0:
                result["failed"] = True
                result["msg"] = "Failed to reset IOD. " + sshstr
            else:
                result["changed"] = True
                result["messages"] = "in-order-delivery-enabled reset"
        else:
            result["failed"] = True
            result["msg"] = "Failed to reset IOD. Invalid input."
        l_diffs.pop("in-order-delivery-enabled")

    if "fabric-principal-priority" in l_diffs and "fabric-principal-enabled" in l_diffs:
        # if both are given, execute the CLI
        if l_diffs["fabric-principal-enabled"] == "true":
            rssh, sshstr = ssh_and_configure(login, password, fos_ip_addr, ssh_hostkeymust, "fabricprincipal --enable -p " + l_diffs["fabric-principal-priority"] + " -f", "Principal Selection Mode enabled")
            if rssh != 0:
                result["failed"] = True
                result["msg"] = "Failed to set fabric-principal. " + sshstr
            else:
                result["changed"] = True
                result["messages"] = "fabric-principal-enabled set"
        elif l_diffs["fabric-principal-enabled"] == "false":
            #if disabling, must set the priority to 0
            if l_diffs["fabric-principal-priority"] != "0":
                result["failed"] = True
                result["msg"] = "Priority must be 0 when disabling"
            else:
                rssh, sshstr = ssh_and_configure(login, password, fos_ip_addr, ssh_hostkeymust, "fabricprincipal --disable", "Principal Selection Mode disabled")
                if rssh != 0:
                    result["failed"] = True
                    result["msg"] = "Failed to set fabric-principal. " + sshstr
                else:
                    result["changed"] = True
                    result["messages"] = "fabric-principal-enabled reset"
        else:
            result["failed"] = True
            result["msg"] = "Failed to set fabric-principal. Invalid input."
        l_diffs.pop("fabric-principal-enabled")
        l_diffs.pop("fabric-principal-priority")
    else:
        if "fabric-principal-priority" in l_diffs:
            enabled_err, enabled, priority_err, priority = fabric_principal(login, password, fos_ip_addr, ssh_hostkeymust)
            if enabled_err is None and enabled:
                rssh, sshstr = ssh_and_configure(login, password, fos_ip_addr, ssh_hostkeymust, "fabricprincipal --enable -p " + l_diffs["fabric-principal-priority"] + " -f", "Principal Selection Mode enabled")
                if rssh != 0:
                    result["failed"] = True
                    result["msg"] = "Failed to set fabric-principal-priority. " + sshstr
                else:
                    result["changed"] = True
                    result["messages"] = "fabric-principal-priority set"
            else:
                result["failed"] = True
                result["msg"] = "fabric-principal-priority must be accompanied by fabric-principal-enabled"
            l_diffs.pop("fabric-principal-priority")

        if "fabric-principal-enable" in l_diffs:
            result["failed"] = True
            result["msg"] = "fabric-principal-enabled must be accompanied by fabric-principal-priority"
            l_diffs.pop("fabric-principal-enabled")

    if len(l_diffs) == 0:
        return 0

    full_fabric_url, validate_certs = full_url_get(is_https,
                                                   fos_ip_addr,
                                                   REST_FABRIC)

    return (url_patch_single_object(fos_ip_addr, is_https, auth,
                                    vfid, result, full_fabric_url,
                                    "fabric", l_diffs, timeout))


def to_human_port_configuration(attributes):
    for k, v in attributes.items():
        if v == "true":
            attributes[k] = True
        elif v == "false":
            attributes[k] = False

    yang_to_human(attributes)


def to_fos_port_configuration(attributes, result):
    human_to_yang(attributes)

    for k, v in attributes.items():
        if isinstance(v, bool):
            if v == True:
                attributes[k] = "true"
            else:
                attributes[k] = "false"

    return 0


def port_configuration_get(login, password, fos_ip_addr, fos_version, is_https, auth, vfid, result, ssh_hostkeymust, timeout):
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
        :return: dict of fabric configurations
        :rtype: dict
    """
    full_port_config_url, validate_certs = full_url_get(is_https,
                                                        fos_ip_addr,
                                                        REST_PORT_CONFIGURATION)

    rtype, rdict = url_get_to_dict(fos_ip_addr, is_https, auth, vfid,
                                   result, full_port_config_url, timeout)
    if rtype != 0:
        result["failed"] = True
        result["msg"] = "API failed to return data"
        return -1, None

    rssh, sshstr = ssh_and_configure(login, password, fos_ip_addr, ssh_hostkeymust, "creditrecovmode --show", "showcommand")
    if rssh == 0:
        if "Internal port credit recovery is Disabled" in sshstr:
            rdict["Response"]["port-configuration"]["credit-recovery-mode"] = "off"
        elif "Internal port credit recovery is Enabled with LrOnly" in sshstr:
            rdict["Response"]["port-configuration"]["credit-recovery-mode"] = "onLrOnly"
        elif "Internal port credit recovery is Enabled with LrThresh" in sshstr:
            rdict["Response"]["port-configuration"]["credit-recovery-mode"] = "onLrThresh"
        elif "Not supported on this platform" in sshstr:
            result["credit_recovery_mode"] = "Not supported on this platform"
        else:
            result["failed"] = True
            result["msg"] = "credit-recovery-mode returned unknown string"
            return -1, None

    return 0, rdict


def port_configuration_patch(login, password, fos_ip_addr, fos_version, is_https, auth, vfid, result, diff_attributes, ssh_hostkeymust, timeout):
    """
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
        :return: dict of port-configuration configurations
        :rtype: dict
    """
    l_diffs = diff_attributes.copy()

    if "credit-recovery-mode" in l_diffs:
        if l_diffs["credit-recovery-mode"] == "off":
            rssh, sshstr = ssh_and_configure(login, password, fos_ip_addr, ssh_hostkeymust, "creditrecovmode --cfg off", "")
            if rssh != 0:
                result["failed"] = True
                result["msg"] = "Failed to set credit-recovery-mode to off. " + sshstr
            else:
                result["changed"] = True
                result["messages"] = "credit-recovery-mode set to off"
        elif l_diffs["credit-recovery-mode"] == "onLrOnly":
            rssh, sshstr = ssh_and_configure(login, password, fos_ip_addr, ssh_hostkeymust, "creditrecovmode --cfg onLrOnly", "")
            if rssh != 0:
                result["failed"] = True
                result["msg"] = "Failed to credit-recovery-mode to onLrOnly. " + sshstr
            else:
                result["changed"] = True
                result["messages"] = "credit-recovery-mode set to onLrOnly"
        elif l_diffs["credit-recovery-mode"] == "onLrThresh":
            rssh, sshstr = ssh_and_configure(login, password, fos_ip_addr, ssh_hostkeymust, "creditrecovmode --cfg onLrThresh", "")
            if rssh != 0:
                result["failed"] = True
                result["msg"] = "Failed to credit-recovery-mode to onLrThresh. "+ sshstr
            else:
                result["changed"] = True
                result["messages"] = "credit-recovery-mode set to onLrThresh"
        else:
            result["failed"] = True
            result["msg"] = "unknown credit-recovery-mode value"
        l_diffs.pop("credit-recovery-mode")

    if len(l_diffs) == 0:
        return 0

    full_port_config_url, validate_certs = full_url_get(is_https,
                                                        fos_ip_addr,
                                                        REST_PORT_CONFIGURATION)

    return (url_patch_single_object(fos_ip_addr, is_https, auth,
                                    vfid, result, full_port_config_url,
                                    "port-configuration", l_diffs, timeout))
