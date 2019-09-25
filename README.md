Brocade Ansible reference example Modules and Playbooks - Prototype code
=======

This repository provides reference example Modules & Playbooks for Ansible
to manage Fibre Channel switches running FOS 8.2.x.

### dependency ###

    Paramiko and xmltodict. Brocade Ansible modules do not require PyFOS.

### env ###

    Add library path to PYTHONPATH and ANSIBLE_LIBRARY variable

    bash example:

        if the repository is cloned under /home/myaccount/ansible,

        export PYTHONPATH="/home/myaccount/ansible/library/ansible/module_utils/storage/brocade"
        export ANSIBLE_LIBRARY="/home/myaccount/ansible/library/ansible/modules/storage/brocade"


### Contact ###

    Automation.BSN@broadcom.com
