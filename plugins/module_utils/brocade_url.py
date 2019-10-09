# Copyright 2019 Broadcom. All rights reserved.
# The term 'Broadcom' refers to Broadcom Inc. and/or its subsidiaries.
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import (absolute_import, division, print_function)
import time
import os
import ansible.module_utils.urls as ansible_urls
import ansible.module_utils.six.moves.urllib.error as urllib_error
from ansible.module_utils.brocade_xml import bsn_xmltodict

__metaclass__ = type


"""
Brocade Connections utils
"""


VF_ID = "?vf-id="
HTTP = "http://"
HTTPS = "https://"


def url_post(fos_ip_addr, is_https, auth, vfid, result, url, body):
    """
        general function to post for a given url

        :param fos_ip_addr: fos switch ip address
        :type fos_ip_addr: str
        :param is_https: indicate to use HTTPS or HTTP
        :type fos_password: Bool
        :param auth: return authorization struct at the time of login
        :type auth: dict
        :param result: dict to store execution results in
        :type result: dict
        :param url: full url
        :type url: str
        :param body: body to post
        :type body: str
        :return: 0 for success or -1 for failure
        :rtype: int
    """
    if vfid is not None and vfid != -1:
        url = url + VF_ID + str(vfid)

    try:
        resp = ansible_urls.open_url(url, body,
                                     headers={
                                         "Authorization": auth["auth"],
                                         'Content-Type':
                                         'application/yang-data+xml'},
                                     method="POST")
    except urllib_error.HTTPError as e:
        result["post_url"] = url
        result["post_resp_code"] = e.code
        result["post_resp_reason"] = e.reason
        ret_code, root_dict = bsn_xmltodict(result, e.read())
        result["post_resp_data"] = root_dict
        result["failed"] = True
        result["msg"] = "url_post failed"
        return -1

    time.sleep(auth["throttle"])

    return 0


def url_patch(fos_ip_addr, is_https, auth, vfid, result, url, body, longer_timeout = None):
    """
        general function to patch for a given url

        :param fos_ip_addr: fos switch ip address
        :type fos_ip_addr: str
        :param is_https: indicate to use HTTPS or HTTP
        :type fos_password: Bool
        :param auth: return authorization struct at the time of login
        :type auth: dict
        :param result: dict to store execution results in
        :type auth: dict
        :param url: full url
        :type url: str
        :param body: body to post
        :type body: str
        :return: 0 for success or -1 for failure
        :rtype: int
    """
    if vfid is not None and vfid != -1:
        url = url + VF_ID + str(vfid)

    if longer_timeout == None:
        try:
            resp = ansible_urls.open_url(url, body,
                                     headers={
                                         "Authorization": auth["auth"],
                                         'Content-Type':
                                         'application/yang-data+xml'},
                                     method="PATCH")
        except urllib_error.HTTPError as e:
            result["patch_url"] = url
            result["patch_resp_code"] = e.code
            result["patch_resp_reason"] = e.reason
            ret_code, root_dict = bsn_xmltodict(result, e.read())
            result["patch_resp_data"] = root_dict
            result["failed"] = True
            result["msg"] = "url_patch failed"
            return -1
    else:
        try:
            resp = ansible_urls.open_url(url, body,
                                     headers={
                                         "Authorization": auth["auth"],
                                         'Content-Type':
                                         'application/yang-data+xml'},
                                     method="PATCH", timeout = longer_timeout)
        except urllib_error.HTTPError as e:
            result["patch_url"] = url
            result["patch_resp_code"] = e.code
            result["patch_resp_reason"] = e.reason
            ret_code, root_dict = bsn_xmltodict(result, e.read())
            result["patch_resp_data"] = root_dict
            result["failed"] = True
            result["msg"] = "url_patch failed"
            return -1

    time.sleep(auth["throttle"])

    return 0


def url_delete(fos_ip_addr, is_https, auth, vfid, result, url, body):
    """
        general function to delete for a given url

        :param fos_ip_addr: fos switch ip address
        :type fos_ip_addr: str
        :param is_https: indicate to use HTTPS or HTTP
        :type fos_password: Bool
        :param auth: return authorization struct at the time of login
        :type auth: dict
        :param result: dict to store execution results in
        :type result: dict
        :param url: full url
        :type url: str
        :param body: body to post
        :type body: str
        :return: 0 for success or -1 for failure
        :rtype: int
    """
    if vfid is not None and vfid != -1:
        url = url + VF_ID + str(vfid)

    try:
        resp = ansible_urls.open_url(url, body,
                                     headers={
                                         "Authorization": auth["auth"],
                                         'Content-Type':
                                         'application/yang-data+xml'},
                                     method="DELETE")
    except urllib_error.HTTPError as e:
        result["delete_url"] = url
        result["delete_resp_code"] = e.code
        result["delete_resp_reason"] = e.reason
        ret_code, root_dict = bsn_xmltodict(result, e.read())
        result["delete_resp_data"] = root_dict
        result["failed"] = True
        result["msg"] = "url_delete failed"
        return -1

    time.sleep(auth["throttle"])

    return 0


def url_get_to_dict(fos_ip_addr, is_https, auth, vfid, result, url):
    """
        retrieve existing url content and return dict

        :param fos_ip_addr: ip address of FOS switch
        :type fos_ip_addr: str
        :param is_https: indicate to use HTTP or HTTPS
        :type is_https: bool
        :param auth: authorization struct from login
        :type auth: dict
        :param result: dict to keep track of execution msgs
        :type result: dict
        :param url: url for FOS REST API
        :type url: str
        :return: code to indicate failure or success
        :rtype: int
        :return: list of dict of port configurations
        :rtype: list
    """
    if vfid is not None and vfid != -1:
        url = url + VF_ID + str(vfid)

    try:
        get_resp = ansible_urls.open_url(url,
                                         headers={
                                             "Authorization": auth["auth"],
                                             'Content-Type':
                                             'application/yang-data+xml'},
                                         method="GET")
    except urllib_error.HTTPError as e:
        e_data = e.read()
        ret_code, root_dict = bsn_xmltodict(result, e_data)
        if e.code == 404 and (root_dict["errors"]["error"]["error-message"] == "No entries found" or root_dict["errors"]["error"]["error-message"] == "No syslog servers are configured"):
            empty_list_resp = {}
            empty_list_resp["Response"] = {}
            empty_list_resp["Response"][os.path.basename(url)] = []
            return 0, empty_list_resp

        result["get_url"] = url
        result["get_resp_code"] = e.code
        result["get_resp_reason"] = e.reason
        result["get_resp_data"] = root_dict
        result["failed"] = True
        result["msg"] = "url_get_to_dict failed"
        return -1, None

    data = get_resp.read()
    ret_code, root_dict = bsn_xmltodict(result, data)
    if ret_code == -1:
        result["failed"] = True
        result["msg"] = "bsn_xmltodict failed"
        return -1, None

    time.sleep(auth["throttle"])

    return 0, root_dict


def url_patch_single_object(fos_ip_addr, is_https, auth, vfid,
                            result, url, obj_name, diff_attributes, longer_timeout = None):
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
        :return: dict of key/value attributes of an object
        :rtype: dict
    """
    diff_str = ""

    diff_str = diff_str + "<" + obj_name + ">\n"
    for k, v in diff_attributes.items():
        if isinstance(v, dict):
            diff_str = diff_str + "<" + k + ">\n"
            for k1, v1 in v.items():
                if isinstance(v1, list):
                    for elem in v1:
                        diff_str = diff_str + "<" + k1 + ">" +\
                            str(elem) + "</" + k1 + ">\n"
                else:
                    diff_str = diff_str + "<" + k1 + ">" + str(v1) +\
                        "</" + k1 + ">\n"
            diff_str = diff_str + "</" + k + ">\n"
        else:
            diff_str = diff_str + "<" + k + ">" + str(v) + "</" + k + ">\n"

    diff_str = diff_str + "</" + obj_name + ">\n"

    result["url"] = url
    result["diff_str"] = diff_str

    if longer_timeout == None:
        return url_patch(fos_ip_addr, is_https, auth, vfid, result,
                         url, diff_str)
    else:
        return url_patch(fos_ip_addr, is_https, auth, vfid, result,
                         url, diff_str, longer_timeout)
