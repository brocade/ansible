#########
Changelog
#########

FOS-Ansible Changelog captures the modifications that are done in the specific FOS Ansible release.

*************************
FOS-Ansible 2.1.0 release
*************************
- Issue #134: Add support for license operations
- Issue #203: vfid with no 'defined-configuration' causes brocade_facts.py to crash
- Issue #204: Meaningless "No start of json char found" error message when SAN switch cannot be connected to
- PR #188: Fix typo in brocade_ssh.py module
- Remove references to SNMP v1 in the documentation and playbooks since they are obsoleted from FOS 10.x
- Replaced protocol with protocol_v2 under suppportsave playbook 
- Remove zoning_to_yaml.py utility script to resolve deprecated dependencies
- Add code_sanity.py script to validate the codebase for lint violations
- Fix majority of the lint violations reported by ansible-lint for playbooks and ruff for python files

Known Issues
============
- brocade_fibrechannel_configuration/fabric URI refactoring needs to be handled correctly

*************************
FOS-Ansible 2.0.2 release
*************************
- Modify firmwaredownload.yml to handle potential timing issues seen under certain conditions

*************************
FOS-Ansible 2.0.1 release
*************************
- Modify firmwaredownload.yml to handle potential timing issues seen under certain conditions

*************************
FOS-Ansible 2.0.1 release
*************************
- Issue #149: brocade_security_certificate_action import cert fails
- Issue #170: brocade_facts: https broken in release 2.0.0
- Issue #180: Please handle PATCH requests that don't change anything appropriately

*************************
FOS-Ansible 2.0.0 release
*************************
- A new module brocade_operation is introduced
- Unified Storage Fabric (USF) functionality is supported using the new module brocade_operation. This includes

    - VRF create, delete, and dhcpConfig
    - VLAN create, delete, interfaceAdd, interfaceRemove, and gatewayConfig
    - ARP create, and delete
    - Interface config, and default
    - StaticRoute create, and delete
    - Lag create, and delete
    - TrafficClass create, delete, memberAdd, and memberRemove

- Configupload support
- Configdownload support
- Configuration upload and download is supported with the help of a new module brocade_scalar_operation
- shebang is updated from python3 to python to support latest python version
- Documentation is updated in playbook to mention renaming of the telnet_timeout to shell_timeout
- Issue related to some times error is ignored is fixed with throwing proper error to upper layers
- Masked logging of the password mentioned in the credentials of the playbook
- Corrected typo in logical switch playbook by removing syslog
