# Copyright 2019 Broadcom. All rights reserved.
# The term 'Broadcom' refers to Broadcom Inc. and/or its subsidiaries.
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import (absolute_import, division, print_function)

__metaclass__ = type


"""
Brocade xml parsing lib
"""

try:
    import xmltodict
    HAS_XMLTODICT = True
except ImportError:
    HAS_XMLTODICT = False


def bsn_xmltodict(result, data):
    """
        converts data into dict and check for xmltodict lib

        :param result: dict to keep track of execution msgs
        :type result: dict
        :param data: xml data in str
        :type data: str
        :param url: url for FOS REST API
        :type url: str
        :return: code to indicate failure or success
        :rtype: int
        :return: dict of data content
        :rtype: dict
    """
    if not HAS_XMLTODICT:
        result["failed"] = True
        result["lxml_err_msg"] = 'The brocade_xml module requires'\
            ' the xmltodict python library installed on the managed machine'
        return -1, None

    try:
        ret_dict = xmltodict.parse(data)
    except xmltodict.expat.ExpatError:
        return -1, data

#    result["xmltodict"] = ret_dict

    return 0, ret_dict
