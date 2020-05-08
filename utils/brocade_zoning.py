# Copyright 2019 Broadcom. All rights reserved.
# The term 'Broadcom' refers to Broadcom Inc. and/or its subsidiaries.
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import (absolute_import, division, print_function)
from ansible.module_utils.brocade_url import url_post, url_patch, url_get_to_dict, url_delete,\
    full_url_get, url_patch_single_object
from ansible.module_utils.brocade_connection import exit_after_login
from ansible.module_utils.brocade_yang import yang_to_human, human_to_yang

__metaclass__ = type


"""
Brocade Zoning utils
"""


REST_DEFINED = "/rest/running/zoning/defined-configuration"
REST_EFFECTIVE = "/rest/running/zoning/effective-configuration"
REST_EFFECTIVE_CHECKSUM = "/rest/running/zoning/"\
    "effective-configuration/checksum"


def to_human_zoning(zoning_config):
    for k, v in zoning_config.items():
        if v == "true":
            zoning_config[k] = True
        elif v == "false":
            zoning_config[k] = False

    if "default-zone-access" in zoning_config:
        if zoning_config["default-zone-access"] == "1":
            zoning_config["default-zone-access"] = "allaccess"
        else:
            zoning_config["default-zone-access"] = "noaccess"

    yang_to_human(zoning_config)

def to_fos_zoning(zoning_config, result):
    human_to_yang(zoning_config)

    if "default-zone-access" in zoning_config:
        if zoning_config["default-zone-access"] == "allaccess":
            zoning_config["default-zone-access"] = "1"
        elif zoning_config["default-zone-access"] == "noaccess":
            zoning_config["default-zone-access"] = "0"
        else:
            result["failed"] = True
            result["msg"] = "default-zone-access converted to unknown value"
            return -1

    for k, v in zoning_config.items():
        if isinstance(v, bool):
            if v == True:
                zoning_config[k] = "true"
            else:
                zoning_config[k] = "false"

    return 0


def cfgname_checksum_get(fos_ip_addr, is_https, auth, vfid, result):
    """
        Gets the current cfgname and checksum of the effective config

        :param fos_ip_addr: fos switch ip address
        :type fos_ip_addr: str
        :param is_https: indicate to use HTTPS or HTTP
        :type fos_password: Bool
        :param auth: authorization struct at the time of login
        :type auth: dict
        :return: -1 if failed or 0 for success
        :rtype: int
        :return: name of the active_cfg or None if failure
        :rtype: str
        :return: returns checksum or 0 if failure
        :rtype: str
    """
    full_effective_url, validate_certs = full_url_get(is_https,
                                                      fos_ip_addr,
                                                      REST_EFFECTIVE)

    ret_code, effective_resp = url_get_to_dict(fos_ip_addr, is_https,
                                               auth, vfid, result,
                                               full_effective_url)
    if ret_code == -1:
        result["failed"] = True
        result["msg"] = "url_get_to_dict failed"
        return -1, None, 0

#    result["cfgname_checksum_resp"] = effective_resp

    effective_config = effective_resp["Response"]["effective-configuration"]

    cfgname = effective_config["cfg-name"]\
        if "cfg-name" in effective_config else None

    return 0, cfgname, effective_config["checksum"]


def cfg_save(fos_ip_addr, is_https, auth, vfid, result, checksum):
    """
        save current transaction buffer

        :param fos_ip_addr: ip address of FOS switch
        :type fos_ip_addr: str
        :param is_https: indicate to use HTTP or HTTPS
        :type is_https: bool
        :param auth: authorization struct from login
        :type auth: dict
        :param result: dict to keep track of execution msgs
        :type result: dict
        :param checksum: current checksum of the database
        :type checksum: str
        :return: code to indicate failure or success
        :rtype: int
    """
    full_effective_url, validate_certs = full_url_get(is_https,
                                                      fos_ip_addr,
                                                      REST_EFFECTIVE)

    save_str = "<effective-configuration><checksum>" + checksum +\
        "</checksum><cfg-action>1</cfg-action></effective-configuration>"
    return url_patch(fos_ip_addr, is_https, auth, vfid, result,
                     full_effective_url, save_str)


def cfg_enable(fos_ip_addr, is_https, auth, vfid,
               result, checksum, active_cfg):
    """
        enable a particular cfg

        :param fos_ip_addr: ip address of FOS switch
        :type fos_ip_addr: str
        :param is_https: indicate to use HTTP or HTTPS
        :type is_https: bool
        :param auth: authorization struct from login
        :type auth: dict
        :param result: dict to keep track of execution msgs
        :type result: dict
        :param checksum: current checksum of the database
        :type checksum: str
        :param active_cfg: cfg to be enabled
        :type active_cfg: str
        :return: code to indicate failure or success
        :rtype: int
    """
    full_effective_url, validate_certs = full_url_get(is_https,
                                                      fos_ip_addr,
                                                      REST_EFFECTIVE)

    save_str = "<effective-configuration><checksum>" + checksum +\
        "</checksum><cfg-name>" + active_cfg +\
        "</cfg-name></effective-configuration>"
    return url_patch(fos_ip_addr, is_https, auth, vfid, result,
                     full_effective_url, save_str)


def cfg_abort(fos_ip_addr, is_https, auth, vfid, result):
    """
        abort zoning transacdtion

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
    """
    full_effective_url, validate_certs = full_url_get(is_https,
                                                      fos_ip_addr,
                                                      REST_EFFECTIVE)

    abort_str = "<effective-configuration><cfg-action>"\
        "4</cfg-action></effective-configuration>"
    return url_patch(fos_ip_addr, is_https, auth, vfid, result,
                     full_effective_url, abort_str)


def zone_post(fos_ip_addr, is_https, auth, vfid, result, zones):
    return zone_set(fos_ip_addr, is_https, auth, vfid, result, zones, "POST")


def zone_patch(fos_ip_addr, is_https, auth, vfid, result, zones):
    return zone_set(fos_ip_addr, is_https, auth, vfid, result, zones, "PATCH")


def zone_delete(fos_ip_addr, is_https, auth, vfid, result, zones):
    return zone_set(fos_ip_addr, is_https, auth, vfid, result, zones, "DELETE")


def zone_set(fos_ip_addr, is_https, auth, vfid, result, zones, method):
    """
        set zones in Zone Database

        :param fos_ip_addr: ip address of FOS switch
        :type fos_ip_addr: str
        :param is_https: indicate to use HTTP or HTTPS
        :type is_https: bool
        :param auth: authorization struct from login
        :type auth: dict
        :param result: dict to keep track of execution msgs
        :type result: dict
        :param zones: list of zones to set
        :type zones: list
        :param method: "POST", "PATCH", or "DELETE"
        :type method: str
        :return: code to indicate failure or success
        :rtype: int
    """
    full_defined_url, validate_certs = full_url_get(is_https,
                                                    fos_ip_addr,
                                                    REST_DEFINED)

    zone_str = "<defined-configuration>"

    for zone in zones:
        zone_str = zone_str + "<zone><zone-name>" +\
            zone["name"] + "</zone-name>"
        # if zone_type is passed, we are talking about an existing
        # zone. keep type type. Otherwise, add the zone type of
        # 1 as peer if pmembers are present
        if "zone_type" in zone:
            zone_str = zone_str + "<zone-type>" + zone["zone_type"] + "</zone-type>"
        else:
            if "principal_members" in zone and len(zone["principal_members"]) > 0:
                zone_str = zone_str + "<zone-type>1</zone-type>"

        if "principal_members" in zone or "members" in zone:
            zone_str = zone_str + "<member-entry>"
        if "principal_members" in zone:
            for member in zone["principal_members"]:
                zone_str = zone_str + "<principal-entry-name>" +\
                    member + "</principal-entry-name>"
        if "members" in zone:
            for member in zone["members"]:
                zone_str = zone_str + "<entry-name>" + member + "</entry-name>"
        if "principal_members" in zone or "members" in zone:
            zone_str = zone_str + "</member-entry>"

        zone_str = zone_str + "</zone>"

    zone_str = zone_str + "</defined-configuration>"

#    result["zone_str"] = zone_str

    if method == "POST":
        return url_post(fos_ip_addr, is_https, auth, vfid, result,
                        full_defined_url, zone_str)
    elif method == "PATCH":
        return url_patch(fos_ip_addr, is_https, auth, vfid, result,
                         full_defined_url, zone_str)
    elif method == "DELETE":
        return url_delete(fos_ip_addr, is_https, auth, vfid, result,
                          full_defined_url, zone_str)
    else:
        result["invalid method"] = method
        result["failed"] = True
        result["msg"] = "url_get_to_dict failed"
        return -1


def zone_get(fos_ip_addr, is_https, auth, vfid, result):
    """
        retrieve existing zones

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
        :return: dict of zone content
        :rtype: dict
    """
    full_defined_url, validate_certs = full_url_get(is_https,
                                                    fos_ip_addr,
                                                    REST_DEFINED + "/zone")

    return url_get_to_dict(fos_ip_addr, is_https, auth,
                           vfid, result, full_defined_url)


def alias_post(fos_ip_addr, is_https, auth, vfid, result, aliases):
    return alias_set(fos_ip_addr, is_https, auth,
                     vfid, result, aliases, "POST")


def alias_patch(fos_ip_addr, is_https, auth, vfid, result, aliases):
    return alias_set(fos_ip_addr, is_https, auth,
                     vfid, result, aliases, "PATCH")


def alias_delete(fos_ip_addr, is_https, auth, vfid, result, aliases):
    return alias_set(fos_ip_addr, is_https, auth,
                     vfid, result, aliases, "DELETE")


def alias_set(fos_ip_addr, is_https, auth, vfid, result, aliases, method):
    """
        set aliases in Zone Database

        :param fos_ip_addr: ip address of FOS switch
        :type fos_ip_addr: str
        :param is_https: indicate to use HTTP or HTTPS
        :type is_https: bool
        :param auth: authorization struct from login
        :type auth: dict
        :param result: dict to keep track of execution msgs
        :type result: dict
        :param aliases: list of aliases to set
        :type aliases: list
        :param method: "POST", "PATCH", or "DELETE"
        :type method: str
        :return: code to indicate failure or success
        :rtype: int
    """
    full_defined_url, validate_certs = full_url_get(is_https,
                                                    fos_ip_addr,
                                                    REST_DEFINED)

    alias_str = "<defined-configuration>"

    for alias in aliases:
        alias_str = alias_str + "<alias><alias-name>" +\
            alias["name"] + "</alias-name>"
        if "members" in alias:
            alias_str = alias_str + "<member-entry>"
            for member in alias["members"]:
                alias_str = alias_str + "<alias-entry-name>" +\
                    member + "</alias-entry-name>"
            alias_str = alias_str + "</member-entry>"
        alias_str = alias_str + "</alias>"

    alias_str = alias_str + "</defined-configuration>"

    result["alias_str"] = alias_str
    result["method"] = method

    if method == "POST":
        return url_post(fos_ip_addr, is_https, auth, vfid, result,
                        full_defined_url, alias_str)
    elif method == "PATCH":
        return url_patch(fos_ip_addr, is_https, auth, vfid, result,
                         full_defined_url, alias_str)
    elif method == "DELETE":
        return url_delete(fos_ip_addr, is_https, auth, vfid, result,
                          full_defined_url, alias_str)
    else:
        result["invalid method"] = method
        result["failed"] = True
        result["msg"] = "url_get_to_dict failed"
        return -1


def alias_get(fos_ip_addr, is_https, auth, vfid, result):
    """
        retrieve existing aliases

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
        :return: dict of alias content
        :rtype: dict
    """
    full_defined_url, validate_certs = full_url_get(is_https,
                                                    fos_ip_addr,
                                                    REST_DEFINED + "/alias")

    return url_get_to_dict(fos_ip_addr, is_https, auth,
                           vfid, result, full_defined_url)


def cfg_post(fos_ip_addr, is_https, auth, vfid, result, cfgs):
    return cfg_set(fos_ip_addr, is_https, auth, vfid, result, cfgs, "POST")


def cfg_patch(fos_ip_addr, is_https, auth, vfid, result, cfgs):
    return cfg_set(fos_ip_addr, is_https, auth, vfid, result, cfgs, "PATCH")


def cfg_delete(fos_ip_addr, is_https, auth, vfid, result, cfgs):
    return cfg_set(fos_ip_addr, is_https, auth, vfid, result, cfgs, "DELETE")


def cfg_set(fos_ip_addr, is_https, auth, vfid, result, cfgs, method):
    """
        set cfgs in Zone Database

        :param fos_ip_addr: ip address of FOS switch
        :type fos_ip_addr: str
        :param is_https: indicate to use HTTP or HTTPS
        :type is_https: bool
        :param auth: authorization struct from login
        :type auth: dict
        :param result: dict to keep track of execution msgs
        :type result: dict
        :param cfgs: list of cfgs to set
        :type cfgs: list
        :param method: "POST", "PATCH", or "DELETE"
        :type method: str
        :return: code to indicate failure or success
        :rtype: int
    """
    full_defined_url, validate_certs = full_url_get(is_https,
                                                    fos_ip_addr,
                                                    REST_DEFINED)

    cfg_str = "<defined-configuration>"

    for cfg in cfgs:
        cfg_str = cfg_str + "<cfg><cfg-name>" + cfg["name"] + "</cfg-name>"
        if "members" in cfg:
            cfg_str = cfg_str + "<member-zone>"
            for member in cfg["members"]:
                cfg_str = cfg_str + "<zone-name>" + member + "</zone-name>"
            cfg_str = cfg_str + "</member-zone>"

        cfg_str = cfg_str + "</cfg>"

    cfg_str = cfg_str + "</defined-configuration>"

#    result["cfg_str"] = cfg_str

    if method == "POST":
        return url_post(fos_ip_addr, is_https, auth, vfid, result,
                        full_defined_url, cfg_str)
    elif method == "PATCH":
        return url_patch(fos_ip_addr, is_https, auth, vfid, result,
                         full_defined_url, cfg_str)
    elif method == "DELETE":
        return url_delete(fos_ip_addr, is_https, auth, vfid, result,
                          full_defined_url, cfg_str)
    else:
        result["invalid method"] = method
        result["failed"] = True
        result["msg"] = "url_get_to_dict failed"
        return -1


def cfg_get(fos_ip_addr, is_https, auth, vfid, result):
    """
        retrieve existing cfgs

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
        :return: dict of cfg content
        :rtype: dict
    """
    full_defined_url, validate_certs = full_url_get(is_https,
                                                    fos_ip_addr,
                                                    REST_DEFINED + "/cfg")

    return url_get_to_dict(fos_ip_addr, is_https, auth,
                           vfid, result, full_defined_url)


def is_wwn(member):
    octets = member.split(":")
    if len(octets) == 8:
        return True
    else:
        return False

def process_member_diff(result, members, current_members):
    a_members = []
    r_members = []
    o_members = []

    if isinstance(current_members, list):
        c_members = current_members
    else:
        c_members = [current_members]

    # find requested members that are not in the current
    # members to see if any needs to be added
    for member in members:
        if is_wwn(member):
            member = member.lower()

        found = False
        for c_member in c_members:
            if member == c_member:
                found = True
                continue
        if found is False:
            a_members.append(member)

    # find current members that are not in the requested
    # members to see if any needs to be removed
    for c_member in c_members:
        found = False
        for member in members:
            if is_wwn(member):
                member = member.lower()

            if member == c_member:
                found = True
                continue
        if found is False:
            r_members.append(c_member)

    # find requested members that are not in to-be-added
    # members to see if any are overlap between requested
    # and current
    for member in members:
        if is_wwn(member):
            member = member.lower()

        found = False
        for a_member in a_members:
            if member == a_member:
                found = True
                continue
        if found is False:
            o_members.append(member)

    return a_members, r_members, o_members


def zoning_common(fos_ip_addr, https, auth, vfid, result, module, input_list,
                  members_add_only, members_remove_only,
                  to_delete_list, type_str, type_diff_processing,
                  type_diff_processing_to_delete, type_get,
                  type_post, type_delete, active_cfg):
    """
        common flow of zone database updates.

        :param fos_ip_addr: ip address of FOS switch
        :type fos_ip_addr: str
        :param is_https: indicate to use HTTP or HTTPS
        :type is_https: bool
        :param auth: authorization struct from login
        :type auth: dict
        :param result: dict to keep track of execution msgs
        :type result: dict
        :param module: AnsibleModule
        :type module: AnsibleModule
        :param input_list: list of zones, aliases or cfgs
        :type input_list: list
        :param to_delete_list: list of zones, aliases or cfgs to delete
        :type to_delete_list: list
        :param type_str: "zone", "alias", or "cfg"
        :type type_str: str
        :param type_diff_processing: function to compare expected & current
        :type type_diff_processing: func
        :param type_diff_processing_to_delete: function to compare to delete & current
        :type type_diff_processing_to_delete: func
        :param type_get: function to get the current db
        :type type_get: func
        :param type_post: function to post to FOS
        :type type_post: func
        :param type_delete: function to delete from FOS
        :type type_delete: func
        :param active_cfg: cfg to be enabled at the end. if None, only saved.
        :type active_cfg: str
        :return: code to indicate failure or success
        :rtype: int
    """

    ret_code, cfgname, checksum = cfgname_checksum_get(fos_ip_addr,
                                                       https, auth,
                                                       vfid, result)
    if ret_code != 0:
        result["failed"] = True
        result['msg'] = "failed to checksum"
        exit_after_login(fos_ip_addr, https, auth, result, module)

    ret_code, get_resp = type_get(fos_ip_addr,
                                  https, auth, vfid, result)
    if ret_code != 0:
        result["failed"] = True
        result['msg'] = "failed to read from database"
        exit_after_login(fos_ip_addr, https, auth, result, module)

    if get_resp is None:
        c_list = []
    else:
        if isinstance(get_resp["Response"][type_str], list):
            c_list = get_resp["Response"][type_str]
        else:
            if get_resp["Response"][type_str] is None:
                c_list = []
            else:
                c_list = [get_resp["Response"][type_str]]

#    result["input_list"] = input_list
#    result["c_list"] = c_list

    if input_list:
        ret_code, post_list, remove_list, common_list = type_diff_processing(result,
                                                                input_list,
                                                                c_list)

        result["post_list"] = post_list
        result["remove_list"] = remove_list
        result["common_list"] = common_list

        # scenarios to return no changes
        # to add list has nothing or
        # add list has something but members_remove_only is True
        # and
        # to remove list has nothing or
        # to remove list has something but members_add_only is True or
        # to remove list has something but member_remove_only is True
        # and
        # common_list has nothing and member_remove_only is True
        # and cfg is not enabled
        if (len(post_list) == 0 or (len(post_list) > 0 and members_remove_only == True)) and (len(remove_list) == 0 or (len(remove_list) > 0 and members_add_only == True) or (len(remove_list) > 0 and members_remove_only == True)) and (members_remove_only == None or (len(common_list) == 0 and members_remove_only == True)) and active_cfg is None:
            exit_after_login(fos_ip_addr, https, auth, result, module)

        need_to_save = False
        if len(post_list) > 0 and (members_remove_only == None or members_remove_only == False):
            if not module.check_mode:
                ret_code = type_post(fos_ip_addr, https, auth, vfid,
                                     result, post_list)
                if ret_code != 0:
                    ret_code = cfg_abort(fos_ip_addr, https,
                                         auth, vfid, result)
                    result["failed"] = True
                    result['msg'] = "HTTP POST failed"
                    exit_after_login(fos_ip_addr, https, auth, result, module)

            need_to_save = True

        if len(remove_list) > 0 and (members_add_only == False or members_add_only == None) and (members_remove_only == None or members_remove_only == False):
            if not module.check_mode:
                ret_code = type_delete(fos_ip_addr, https, auth, vfid,
                                       result, remove_list)
                if ret_code != 0:
                    ret_code = cfg_abort(fos_ip_addr, https,
                                         auth, vfid, result)
                    result["failed"] = True
                    result['msg'] = "HTTP DELETE failed"
                    exit_after_login(fos_ip_addr, https, auth, result, module)

            need_to_save = True

        if len(common_list) > 0 and (members_remove_only == True):
            if not module.check_mode:
                ret_code = type_delete(fos_ip_addr, https, auth, vfid,
                                       result, common_list)
                if ret_code != 0:
                    ret_code = cfg_abort(fos_ip_addr, https,
                                         auth, vfid, result)
                    result["failed"] = True
                    result['msg'] = "HTTP DELETE common failed"
                    exit_after_login(fos_ip_addr, https, auth, result, module)

            need_to_save = True

        if active_cfg is None:
            if need_to_save:
                if not module.check_mode:
                    # if something changed and there is already an active cfg
                    # reenable that cfg
                    ret_code = 0
                    failed_msg = ""
                    if cfgname is not None:
                        failed_msg = "CFG ENABLE failed"
                        ret_code = cfg_enable(fos_ip_addr, https, auth, vfid,
                                            result, checksum, cfgname)
                    else:
                        failed_msg = "CFG SAVE failed"
                        ret_code = cfg_save(fos_ip_addr, https, auth, vfid,
                                        result, checksum)
                    if ret_code != 0:
                        ret_code = cfg_abort(fos_ip_addr, https,
                                             auth, vfid, result)
                        result['msg'] = failed_msg
                        result["failed"] = True
                        exit_after_login(fos_ip_addr, https, auth,
                                         result, module)

                result["changed"] = True
        else:
            if need_to_save or cfgname != active_cfg:
                if not module.check_mode:
                    ret_code = cfg_enable(fos_ip_addr, https, auth, vfid,
                                        result, checksum, active_cfg)
                    if ret_code != 0:
                        ret_code = cfg_abort(fos_ip_addr, https,
                                            auth, vfid, result)
                        result['msg'] = "CFG ENABLE failed"
                        result["failed"] = True
                        exit_after_login(fos_ip_addr, https, auth, result, module)

                result["changed"] = True

    if to_delete_list:
        need_to_save = False

        ret_code, delete_list = type_diff_processing_to_delete(result,
                                                               to_delete_list,
                                                               c_list)

        result["delete_list"] = delete_list

        if len(delete_list) == 0:
            return 0

        if not module.check_mode:
            ret_code = type_delete(fos_ip_addr, https, auth, vfid,
                                   result, delete_list)
            if ret_code != 0:
                ret_code = cfg_abort(fos_ip_addr, https, auth, vfid, result)
                result["failed"] = True
                result['msg'] = "HTTP DELETE failed"
                exit_after_login(fos_ip_addr, https, auth, result, module)

            need_to_save = True

        if active_cfg is None:
            if need_to_save:
                if not module.check_mode:
                    ret_code = 0
                    failed_msg = ""
                    if cfgname is not None:
                        failed_msg = "CFG ENABLE failed"
                        ret_code = cfg_enable(fos_ip_addr, https, auth, vfid,
                                            result, checksum, cfgname)
                    else:
                        failed_msg = "CFG SAVE failed"
                        ret_code = cfg_save(fos_ip_addr, https, auth, vfid,
                                        result, checksum)
                    if ret_code != 0:
                        ret_code = cfg_abort(fos_ip_addr, https, auth,
                                             vfid, result)
                        result["failed"] = True
                        result['msg'] = failed_msg
                        exit_after_login(fos_ip_addr, https, auth,
                                         result, module)

                result["changed"] = True
        else:
            if not module.check_mode:
                ret_code = cfg_enable(fos_ip_addr, https, auth,
                                      result, checksum, active_cfg)
                if ret_code != 0:
                    ret_code = cfg_abort(fos_ip_addr, https,
                                         auth, result)
                    result["failed"] = True
                    result['msg'] = "CFG ENABLE failed"
                    exit_after_login(fos_ip_addr, https, auth, result, module)

            result["changed"] = True

    return 0


def defined_get(fos_ip_addr, is_https, auth, vfid, result):
    """
        retrieve all of defined Zone Database

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
        :return: dict of full defined Zone DB content
        :rtype: dict
    """
    full_defined_url, validate_certs = full_url_get(is_https,
                                                    fos_ip_addr,
                                                    REST_DEFINED)

    return url_get_to_dict(fos_ip_addr, is_https, auth,
                           vfid, result, full_defined_url)


def effective_get(fos_ip_addr, is_https, auth, vfid, result):
    """
        retrieve all of effective Zone Database

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
        :return: dict of full effective Zone DB content
        :rtype: dict
    """
    full_effective_url, validate_certs = full_url_get(is_https,
                                                      fos_ip_addr,
                                                      REST_EFFECTIVE)

    return url_get_to_dict(fos_ip_addr, is_https, auth,
                           vfid, result, full_effective_url)


def effective_patch(fos_ip_addr, is_https, auth,
                    vfid, result, diff_attributes):
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
        :return: dict of effective configurations
        :rtype: dict
    """
    full_effective_url, validate_certs = full_url_get(is_https,
                                                      fos_ip_addr,
                                                      REST_EFFECTIVE)

    return (url_patch_single_object(fos_ip_addr, is_https, auth,
            vfid, result, full_effective_url,
            "effective-configuration", diff_attributes))
