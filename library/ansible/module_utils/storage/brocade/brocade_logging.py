# Copyright: (c) 2019, Broadcom
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
from brocade_url import url_get_to_dict, url_patch, HTTP, HTTPS, url_patch_single_object, url_post, url_delete
from brocade_yang import yang_to_human, human_to_yang

__metaclass__ = type


"""
Brocade logging utils
"""


REST_LOGGING_AUDIT = "/rest/running/brocade-logging/audit"
REST_LOGGING_SYSLOG_SERVER = "/rest/running/brocade-logging/syslog-server"


def to_human_syslog_server(server):
    for k, v in server.items():
        if v == "true":
            server[k] = True
        elif v == "false":
            server[k] = False

    yang_to_human(server)


def to_fos_syslog_server(server, result):
    human_to_yang(server)

    for k, v in server.items():
        if isinstance(v, bool):
            if v == True:
                server[k] = "true"
            else:
                server[k] = "false"

    return 0


def syslog_server_get(fos_ip_addr, is_https, auth, vfid, result):
    """
        retrieve existing syslog-server configurations

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
    full_url = (HTTPS if is_https else HTTP) +\
        fos_ip_addr + REST_LOGGING_SYSLOG_SERVER

    return (url_get_to_dict(fos_ip_addr, is_https, auth, vfid,
                              result, full_url))


def syslog_server_patch(fos_ip_addr, is_https, auth,
                       vfid, result, servers):
    """
        update existing syslog-server configurations

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
    full_url = (HTTPS if is_https else HTTP) +\
        fos_ip_addr + REST_LOGGING_SYSLOG_SERVER

    syslog_str = ""

    for server in servers:
        syslog_str = syslog_str + "<syslog-server>"

        syslog_str = syslog_str + "<server>" + server["server"] + "</server>"

        for k, v in server.items():
            if k != "server":
                k = k.replace("_", "-")
                syslog_str = syslog_str + "<" + k + ">" +\
                    str(v) + "</" + k + ">"

        syslog_str = syslog_str + "</syslog-server>"

    result["patch_syslog_str"] = syslog_str

    return url_patch(fos_ip_addr, is_https, auth, vfid, result,
                     full_url, syslog_str)


def syslog_server_post(fos_ip_addr, is_https, auth,
                       vfid, result, servers):
    """
        add to syslog-server configurations

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
    full_url = (HTTPS if is_https else HTTP) +\
        fos_ip_addr + REST_LOGGING_SYSLOG_SERVER

    syslog_str = ""

    for server in servers:
        syslog_str = syslog_str + "<syslog-server>"

        syslog_str = syslog_str + "<server>" + server["server"] + "</server>"

        for k, v in server.items():
            if k != "server":
                k = k.replace("_", "-")
                syslog_str = syslog_str + "<" + k + ">" +\
                    str(v) + "</" + k + ">"

        syslog_str = syslog_str + "</syslog-server>"

    result["post_syslog_str"] = syslog_str

    return url_post(fos_ip_addr, is_https, auth, vfid, result,
                     full_url, syslog_str)


def syslog_server_delete(fos_ip_addr, is_https, auth,
                       vfid, result, servers):
    """
        delete existing syslog-server configurations

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
    full_url = (HTTPS if is_https else HTTP) +\
        fos_ip_addr + REST_LOGGING_SYSLOG_SERVER

    syslog_str = ""

    for server in servers:
        syslog_str = syslog_str + "<syslog-server>"

        syslog_str = syslog_str + "<server>" + server["server"] + "</server>"

        for k, v in server.items():
            if k != "server":
                k = k.replace("_", "-")
                syslog_str = syslog_str + "<" + k + ">" +\
                    str(v) + "</" + k + ">"

        syslog_str = syslog_str + "</syslog-server>"

    result["delete_syslog_str"] = syslog_str

    return url_delete(fos_ip_addr, is_https, auth, vfid, result,
                     full_url, syslog_str)


def to_human_audit(attributes):
    for k, v in attributes.items():
        if v == "true":
            attributes[k] = True
        elif v == "false":
            attributes[k] = False

    yang_to_human(attributes)

def to_fos_audit(attributes, result):
    human_to_yang(attributes)

    for k, v in attributes.items():
        if isinstance(v, bool):
            if v == True:
                attributes[k] = "true"
            else:
                attributes[k] = "false"

    return 0


def audit_get(fos_ip_addr, is_https, auth, vfid, result):
    """
        retrieve existing audit configurations

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
    full_url = (HTTPS if is_https else HTTP) +\
        fos_ip_addr + REST_LOGGING_AUDIT

    return url_get_to_dict(fos_ip_addr, is_https, auth, vfid,
                           result, full_url)


def audit_patch(fos_ip_addr, is_https, auth,
                       vfid, result, diff_attributes):
    """
        update existing audit configurations

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
    full_url = (HTTPS if is_https else HTTP) +\
        fos_ip_addr + REST_LOGGING_AUDIT

    return (url_patch_single_object(fos_ip_addr, is_https, auth,
                                    vfid, result, full_url,
                                    "audit", diff_attributes))
