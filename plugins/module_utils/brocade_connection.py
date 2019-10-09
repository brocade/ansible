# Copyright 2019 Broadcom. All rights reserved.
# The term 'Broadcom' refers to Broadcom Inc. and/or its subsidiaries.
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import (absolute_import, division, print_function)
import base64
import time
import ansible.module_utils.urls as ansible_urls
import ansible.module_utils.six.moves.urllib.error as urllib_error
from ansible_collections.daniel_chung_broadcom.fos.plugins.module_utils.brocade_xml import bsn_xmltodict
from ansible_collections.daniel_chung_broadcom.fos.plugins.module_utils.brocade_url import url_post, HTTP, HTTPS, url_get_to_dict


__metaclass__ = type


"""
Brocade Connections utils
"""

DEFAULT_THROTTLE = 1.1
REST_LOGIN = "/rest/login"
REST_LOGOUT = "/rest/logout"
REST_SWITCH = "/rest/running/brocade-fibrechannel-switch/fibrechannel-switch"


def login(fos_ip_addr, fos_user_name, fos_password, is_https, throttle, result):
    """
        login to the fos switch at ip address specified

        :param fos_ip_addr: fos switch ip address
        :type fos_ip_addr: str
        :param fos_user_name: login name
        :type fos_user_name: str
        :param fos_password: password
        :type fos_password: password
        :param is_https: indicate to use HTTPS or HTTP
        :type fos_password: Bool
        :param throttle: throttle delay
        :type fos_password: float
        :return: returned header, None if not successfully logged in
        :rtype: dict
    """
    full_login_url = (HTTPS if is_https else HTTP) + fos_ip_addr + REST_LOGIN
    logininfo = fos_user_name + ":" + fos_password
    login_encoded = base64.b64encode(logininfo.encode())

    credential = {"Authorization": "Basic " + login_encoded.decode(),
                  "User-Agent": "Rest-Conf"}
    try:
        login_resp = ansible_urls.open_url(full_login_url, headers=credential,
                                           method="POST")
    except urllib_error.HTTPError as e:
        result["login_resp_code"] = e.code
        result["login_resp_reason"] = e.reason
        ret_code, root_dict = bsn_xmltodict(result, e.read())
        result["login_resp_data"] = root_dict
        result["failed"] = True
        result["msg"] = "failed to login"
        return -1, None, None

    full_switch_url = (HTTPS if is_https else HTTP) + fos_ip_addr + REST_SWITCH

    auth = {}
    auth["auth"] = login_resp.info()["Authorization"]
    if throttle == None:
        auth["throttle"] = DEFAULT_THROTTLE
    else:
        auth["throttle"] = throttle

    # get fos version from the default switch
    rtype, rdict = url_get_to_dict(fos_ip_addr, is_https, auth, -1,
                                           result, full_switch_url)
    if rtype != 0:
        result["failed"] = True
        result["msg"] = "API failed to return switch firmware version"
        logout(fos_ip_addr, is_https, auth, result)
        return -1, None, None

    time.sleep(auth["throttle"] * 2)

    return 0, auth, rdict["Response"]["fibrechannel-switch"]["firmware-version"]


def logout(fos_ip_addr, is_https, auth, result):
    """
        logout from the fos switch at ip address specified

        :param fos_ip_addr: fos switch ip address
        :type fos_ip_addr: str
        :param is_https: indicate to use HTTPS or HTTP
        :type fos_password: Bool
        :param auth: return authorization struct at the time of login
        :type auth: dict
        :return: 0 for success or -1 for failure
        :rtype: int
    """
    full_logout_url = (HTTPS if is_https else HTTP) +\
        fos_ip_addr + REST_LOGOUT

    return url_post(fos_ip_addr, is_https, auth, None,
                    result, full_logout_url, None)


def exit_after_login(fos_ip_addr, https, auth, result, module):
    """
        module exit but logout first

        :param fos_ip_addr: fos switch ip address
        :type fos_ip_addr: str
        :param is_https: indicate to use HTTPS or HTTP
        :type fos_password: Bool
        :param auth: return authorization struct at the time of login
        :type auth: dict
        :param result: accumulated result dict
        :param module: AnsibleModule
        :type module: AnsibleModule
        :return: 0
        :rtype: int
    """
    logout(fos_ip_addr, https, auth, result)
    module.exit_json(**result)
    return 0
