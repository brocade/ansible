#########
Changelog
#########

FOS-Ansible Changelog captures the modifications that are done in the specific FOS Ansible release.

*************************
FOS-Ansible 2.1.0 release
*************************
- Add code_sanity.py script to validate the codebase for lint violations
- Fix majority of the lint violations reported by ansible-lint for playbooks and ruff for python files
- Remove zoning_to_yaml.py utility script to resolve deprecated dependencies
- Remove references to SNMP v1 in the documentation and playbooks since they are obsoleted in FOS 10.0.x
- Fix typo in brocade_ssh.py module as suggested by PR #188

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
- Issue #149/FOSANS-128: brocade_security_certificate_action import cert fails
- Issue #170/FOSANS-132: brocade_facts: https broken in release 2.0.0
- Issue #180/FOSANS-123: Please handle PATCH requests that don't change anything appropriately

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
