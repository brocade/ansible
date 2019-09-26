# Copyright 2019 Broadcom. All rights reserved.
# The term 'Broadcom' refers to Broadcom Inc. and/or its subsidiaries.
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import (absolute_import, division, print_function)

__metaclass__ = type


"""
Brocade yang utilities
"""

def yang_to_human(attributes):
    yang_attributes = {}
    for k, v in attributes.items():
        if isinstance(v, dict):
            dict_v = {}
            for k1, v1 in v.items():
                dict_v[k1.replace("-", "_")] = v1
            yang_attributes[k.replace("-", "_")] = dict_v
        else:
            yang_attributes[k.replace("-", "_")] = v

    attributes.clear()
    for k, v in yang_attributes.items():
        attributes[k] = v

    
def human_to_yang(attributes):
    human_attributes = {}
    for k, v in attributes.items():
        if isinstance(v, dict):
            dict_v = {}
            for k1, v1 in v.items():
                dict_v[k1.replace("_", "-")] = v1
            human_attributes[k.replace("_", "-")] = dict_v
        else:
            human_attributes[k.replace("_", "-")] = v

    attributes.clear()
    for k, v in human_attributes.items():
        attributes[k] = v


def find_diff(result, yang_key, new_value, c_config, diff_attributes):
    if yang_key in c_config:
        if isinstance(new_value, bool):
            # first convert the string to real boolean
            # then you can compare to new value to see if 
            # the attribute to be set to which string boolean values
            c_bool = c_config[yang_key]
            if new_value != c_bool:
                if new_value is True:
                    diff_attributes[yang_key] = True
                else:
                    diff_attributes[yang_key] = False
        elif isinstance(new_value, dict):
            # if the new value is dict, just recursively
            # deal with the content
            for k, v in new_value.items():
                yang_k = k
                diff_attributes[yang_key] = {}
                find_diff(result, yang_k, v, c_config[yang_key], diff_attributes[yang_key])
            if len(diff_attributes[yang_key]) == 0:
                diff_attributes.pop(yang_key)
        elif isinstance(new_value, list):
            # if the new value is a list, compare the diff
            if len(new_value) != len(c_config[yang_key]):
                diff_attributes[yang_key] = new_value 
            else:
                for nentry in new_value:
                    found = False
                    for centry in c_config[yang_key]:
                        if nentry == centry:
                            found = True 
                    if not found:
                        diff_attributes[yang_key] = new_value 
        else:
            if str(new_value) != c_config[yang_key]:
                diff_attributes[yang_key] = new_value 
    else:
        # if the key doesn't exist in the current config
        # just mark it as different using the new vlaue
        diff_attributes[yang_key] = new_value


def generate_diff(result, c_config, n_config):
    """
        generates the diff list between current & new config

        :param result: dict to keep track of execution msgs
        :type result: dict
        :param c_config: dict of current config
        :type c_config: dict
        :param n_config: dict of new config
        :type n_config: dict
        :return: dict of diff list
        :rtype: dict
    """

    diff_attributes = {}

    if n_config is not None:
        for k, v in n_config.items():
            yang_key = k
            find_diff(result, yang_key, v, c_config, diff_attributes)

    return diff_attributes
