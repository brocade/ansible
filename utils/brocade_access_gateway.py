# Copyright 2019 Broadcom. All rights reserved.
# The term 'Broadcom' refers to Broadcom Inc. and/or its subsidiaries.
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import (absolute_import, division, print_function)
from ansible.module_utils.brocade_url import url_get_to_dict, url_patch, full_url_get
from ansible.module_utils.brocade_yang import yang_to_human, human_to_yang, str_to_human

__metaclass__ = type


"""
Brocade Fibre Channel AG utils
"""


zero_one_attributes = [
    "port-group-policy-enabled",
    "auto-policy-enabled",
    ]


def to_human_access_gateway_policy(config):
    for attrib in zero_one_attributes:
        if str_to_human(attrib) in config:
            if config[str_to_human(attrib)] == "0":
                config[str_to_human(attrib)] = False
            else:
                config[str_to_human(attrib)] = True


def to_fos_access_gateway_policy(config, result):
    for attrib in zero_one_attributes:
        if attrib in config:
            if isinstance(config[attrib], bool):
                if config[attrib] == False:
                    config[attrib] = "0"
                else:
                    config[attrib] = "1"
            else:
                result["failed"] = True
                result["msg"] = attrib + " converted non-bool value"
                return -1

    return 0
