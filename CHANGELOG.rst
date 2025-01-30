FOS-Ansible Changelog
=====================

FOS-Ansible Changelog captures the modifications that are done in the specific FOS Ansible release.

FOS-Ansible 2.0.0 release
-------------------------
- Unified Storage Fabric (USF) functionality is supported
  This includes VRF create, delete, and dhcpConfig
                VLAN create, delete, interfaceAdd, interfaceRemove, and gatewayConfig
                ARP create, and delete
                Interface config, and default
                StaticRoute create, and delete
                Lag create, and delete
                TrafficClass create, delete, memberAdd, and memberRemove

                A new module brocade_operation is introduced to support the above functionality

- Configupload support
- Configdownload support
  Configuration upload and download is supported with the help of a new module brocade_scalar_operation

- shebang is updated from python3 to python to support latest python version
- Documentation is updated in playbook to mention renaming of the telnet_timeout to shell_timeout
- Issue related to some times error is ignored is fixed with throwing proper error to upper layers
- Masked logging of the password mentioned in the credentials of the playbook
- Corrected typo in logical switch playbook by removing syslog
- Tested with Ansible module 10.3.0 (core 2.17.7) running Python 3.11.0
