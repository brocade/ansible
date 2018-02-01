# https://github.com/brocade/ansible
Brocade Ansible reference example Modules and Playbooks - Prototype code
=======

This repository provides reference example Modules & Playbooks for Ansible
to manage Fibre Channel switches.

### dependency ###

    These modules require PyFOS. Please refer to github.com/brocade/pyfos
    repository for PyFOS details.

### env ###

    Add library path to ANSIBLE_LIBRARY variable

    bash example:

        if the repository is cloned under ~myaccount/brocade/ansible,

        export ANSIBLE_LIBRARY=$ANSIBLE_LIBRARY:~myaccount/brocade/ansible/library

### Contact ###

    Automation.BSN@broadcom.com
