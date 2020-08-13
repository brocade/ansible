# Copyright 2019 Broadcom. All rights reserved.
# The term 'Broadcom' refers to Broadcom Inc. and/or its subsidiaries.
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import (absolute_import, division, print_function)
import base64
import time
import ansible.module_utils.urls as ansible_urls
import ansible.module_utils.six.moves.urllib.error as urllib_error
from ansible.module_utils.brocade_xml import bsn_xmltodict
from ansible.module_utils.brocade_url import url_post, full_url_get, url_get_to_dict, url_helper, ERROR_GENERIC, ERROR_SERVER_BUSY


__metaclass__ = type


"""
Brocade Connections utils
"""

DEFAULT_THROTTLE = 4
REST_LOGIN = "/rest/login"
REST_LOGOUT = "/rest/logout"
REST_SWITCH = "/rest/running/brocade-fibrechannel-switch/fibrechannel-switch"


def login(fos_ip_addr, fos_user_name, fos_password, is_https, throttle, result, timeout):
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
    full_login_url, validate_certs = full_url_get(is_https,
                                                  fos_ip_addr,
                                                  REST_LOGIN)
    logininfo = fos_user_name + ":" + fos_password
    login_encoded = base64.b64encode(logininfo.encode())

    credential = {"Authorization": "Basic " + login_encoded.decode(),
                  "User-Agent": "Rest-Conf"}

    retval, eret, edict, login_resp = url_helper(full_login_url, None, "POST", None, result, validate_certs, timeout, credential=credential)
    if retval == ERROR_GENERIC:
        if eret == ERROR_SERVER_BUSY:
            if throttle == None:
                time.sleep(DEFAULT_THROTTLE)
            else:
                time.sleep(throttle)
            retval, eret, edict, login_resp = url_helper(full_login_url, None, "POST", None, result, validate_certs, timeout, credential=credential)
            if retval == ERROR_GENERIC:
                return eret, None, None
        else:
            return eret, None, None

    full_switch_url, validate_certs = full_url_get(is_https,
                                                   fos_ip_addr,
                                                   REST_SWITCH)

    auth = {}
    auth["auth"] = login_resp.info()["Authorization"]
    if throttle == None:
        auth["throttle"] = DEFAULT_THROTTLE
    else:
        auth["throttle"] = throttle

    # get fos version from the default switch
    rtype, rdict = url_get_to_dict(fos_ip_addr, is_https, auth, -1,
                                           result, full_switch_url, timeout)
    if rtype != 0:
        result["failed"] = True
        result["msg"] = "API failed to return switch firmware version"
        logout(fos_ip_addr, is_https, auth, result, timeout)
        return -1, None, None

#    time.sleep(auth["throttle"] * 2)

    return 0, auth, rdict["Response"]["fibrechannel-switch"]["firmware-version"]


def logout(fos_ip_addr, is_https, auth, result, timeout):
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
    full_logout_url, validate_certs = full_url_get(is_https,
                                                   fos_ip_addr,
                                                   REST_LOGOUT)

    return url_post(fos_ip_addr, is_https, auth, None,
                    result, full_logout_url, None, timeout)


def exit_after_login(fos_ip_addr, https, auth, result, module, timeout):
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
    logout(fos_ip_addr, https, auth, result, timeout)
    module.exit_json(**result)
    return 0
