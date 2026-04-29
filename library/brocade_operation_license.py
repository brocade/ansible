# Copyright 2019-2026 Broadcom. All rights reserved.
# The term 'Broadcom' refers to Broadcom Inc. and/or its subsidiaries


from __future__ import absolute_import, division, print_function

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.brocade_objects import operation_helper

__metaclass__ = type


DOCUMENTATION = """

module: brocade_operation_license
short_description: Brocade Fibre Channel license operation
version_added: '2.7'
author: Broadcom BSN Ansible Team <Automation.BSN@broadcom.com>
description:
- Perform license install, remove, or export operations on a Brocade switch.

options:
    credential:
        description:
        - Login information
        suboptions:
            fos_ip_addr:
                description:
                - IP address of the FOS switch
                required: true
                type: str
            fos_user_name:
                description:
                - Login name of FOS switch
                required: true
                type: str
            fos_password:
                description:
                - Password of FOS switch
                required: true
                type: str
            https:
                description:
                - Encryption to use. True for HTTPS, self for self-signed HTTPS,
                  or False for HTTP
                choices:
                    - True
                    - False
                    - self
                required: true
                type: str

        type: dict
        required: true
    vfid:
        description:
        - VFID of the switch. Use -1 for FOS without VF enabled or AG.
        type: int
        required: false
    throttle:
        description:
        - Throttling delay in seconds. Enables second retry on first
          failure.
        type: int
    timeout:
        description:
        - REST timeout in seconds for operations that take longer than FOS
          default value.
        type: int
    license:
        description:
        - License operation input parameters. All attributes correspond to the
          license-parameters container in the brocade-operation-license YANG
          model (revision 2024-10-03). Hyphens in YANG leaf names are replaced
          by underscores.
        - The required sub-parameters depend on the action and transfer method.
          license_payload is valid only for action install when name and host
          are not specified.
          usb_file_path is valid for action install when name, host, and
          license_payload are not specified, or for action export when host
          and license_payload are not specified.
          usb_directory_path is valid only for action export when host and
          license_payload are not specified.
          The remote server parameters host, user_name, password,
          remote_directory, protocol, port, and remote_file are valid for
          action install or export when license_payload and usb_file_path
          are not specified.
        required: true
        type: dict
        suboptions:
            action:
                description:
                - Action to perform on the license. One of install, remove,
                  or export.
                choices: [install, remove, export]
                required: true
                type: str
            name:
                description:
                - License key (e.g. 'license')
                  or serial number (e.g. 'FOS-00-0-02-11201234'). Required for
                  install by key, remove, and targeted export. Not needed when
                  installing from a file, payload, or remote server.
                required: false
                type: str
            license_payload:
                description:
                - Base64-encoded license certificate content (RFC 3414).
                  Use only when action is install and name and host are not
                  specified.
                required: false
                type: str
            usb_file_path:
                description:
                - Relative path of the license certificate on a USB device.
                  Use for action install when name, host, and license_payload
                  are not specified, or for action export when host and
                  license_payload are not specified.
                required: false
                type: str
            usb_directory_path:
                description:
                - USB directory path for exporting license certificates.
                  Use only when action is export and host and license_payload
                  are not specified.
                required: false
                type: str
            host:
                description:
                - IP address or host name of the remote server. Use when
                  action is install or export and license_payload and
                  usb_file_path are not specified.
                required: false
                type: str
            user_name:
                description:
                - User name for the remote server. Required when host is
                  specified.
                required: false
                type: str
            password:
                description:
                - Password for the remote server. Required when host is
                  specified. The module encodes this value automatically
                  before sending to FOS. This value is not logged.
                required: false
                type: str
                no_log: true
            remote_directory:
                description:
                - Directory path on the remote server for license transfer.
                  Required when host is specified.
                required: false
                type: str
            protocol:
                description:
                - Transport protocol for remote server transfer. Required when
                  host is specified.
                choices: [scp, sftp]
                required: false
                type: str
            port:
                description:
                - Port number for scp or sftp (1..65535). Optional when host
                  is specified.
                required: false
                type: int
            remote_file:
                description:
                - Remote file name for exporting a license certificate to a
                  specific file. Optional when host is specified.
                required: false
                type: str

"""


EXAMPLES = """

  gather_facts: False

  vars:
    credential:
      fos_ip_addr: "{{fos_ip_addr}}"
      fos_user_name: admin
      fos_password: xxxx
      https: False

  tasks:

  - name: install license using license key
    brocade_operation_license:
      credential: "{{credential}}"
      vfid: -1
      license:
        name: "xxx-xx-xx-xx-xxxxxxx"
        action: "install"

  - name: install license from remote server
    brocade_operation_license:
      credential: "{{credential}}"
      vfid: -1
      license:
        action: "install"
        host: "192.168.1.100"
        user_name: "user_name"
        password: "user_password"
        remote_directory: "/remote_license_directory"
        protocol: "scp"

  - name: install license from USB
    brocade_operation_license:
      credential: "{{credential}}"
      vfid: -1
      license:
        action: "install"
        usb_file_path: "remote_license_directory/my_license.xml"

  - name: remove license
    brocade_operation_license:
      credential: "{{credential}}"
      vfid: -1
      license:
        name: "xxx-xx-xx-xx-xxxxxxx"
        action: "remove"

  - name: export all license certificates to remote server
    brocade_operation_license:
      credential: "{{credential}}"
      vfid: -1
      license:
        action: "export"
        host: "192.168.1.100"
        user_name: "user_name"
        password: "user_password"
        remote_directory: "/remote_license_directory"
        protocol: "scp"

  - name: export specific license certificate to remote file
    brocade_operation_license:
      credential: "{{credential}}"
      vfid: -1
      license:
        name: "xxx-xx-xx-xx-xxxxxxx"
        action: "export"
        host: "192.168.1.100"
        user_name: "user_name"
        password: "user_password"
        remote_directory: "/remote_license_directory"
        remote_file: "my_license.xml"
        protocol: "scp"

  - name: export all license certificates to USB
    brocade_operation_license:
      credential: "{{credential}}"
      vfid: -1
      license:
        action: "export"
        usb_directory_path: "/usb_license_directory"

"""


RETURN = """

msg:
    description: Success message
    returned: success
    type: str

"""


"""
Brocade Fibre Channel license operation
"""


def main():
    """
    Main function
    """

    argument_spec = dict(
        credential=dict(
            required=True,
            type="dict",
            options=dict(
                fos_ip_addr=dict(required=True, type="str"),
                fos_user_name=dict(required=True, type="str"),
                fos_password=dict(required=True, type="str", no_log=True),
                https=dict(required=True, type="str"),
                ssh_hostkeymust=dict(required=False, type="bool"),
            ),
        ),
        vfid=dict(required=False, type="int"),
        throttle=dict(required=False, type="int"),
        timeout=dict(required=False, type="int"),
        license=dict(
            required=True,
            type="dict",
            options=dict(
                name=dict(required=False, type="str"),
                action=dict(required=True, type="str"),
                license_payload=dict(required=False, type="str"),
                usb_file_path=dict(required=False, type="str"),
                usb_directory_path=dict(required=False, type="str"),
                host=dict(required=False, type="str"),
                user_name=dict(required=False, type="str"),
                password=dict(required=False, type="str", no_log=True),
                remote_directory=dict(required=False, type="str"),
                protocol=dict(required=False, type="str"),
                port=dict(required=False, type="int"),
                remote_file=dict(required=False, type="str"),
            ),
        ),
    )

    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)

    input_params = module.params

    fos_ip_addr = input_params["credential"]["fos_ip_addr"]
    fos_user_name = input_params["credential"]["fos_user_name"]
    fos_password = input_params["credential"]["fos_password"]
    https = input_params["credential"]["https"]
    ssh_hostkeymust = True
    if "ssh_hostkeymust" in input_params["credential"]:
        ssh_hostkeymust = input_params["credential"]["ssh_hostkeymust"]
    throttle = input_params["throttle"]
    timeout = input_params["timeout"]
    vfid = input_params["vfid"]
    license = input_params["license"]
    result = {"changed": False}

    operation_helper(
        module,
        fos_ip_addr,
        fos_user_name,
        fos_password,
        https,
        ssh_hostkeymust,
        throttle,
        vfid,
        "license",
        "license_parameters",
        license,
        result,
        timeout,
    )


if __name__ == "__main__":
    main()
