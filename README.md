## Repository Information 
 Repo URL: https://github.gwd.broadcom.net/BSN/ansible-fos

Brocade Ansible reference example Modules and Playbooks - Prototype code
=======

This repository provides reference example Modules & Playbooks for Ansible
to manage Fibre Channel switches running FOS 8.2.x.

### dependency ###

    Paramiko and xmltodict. BSN Ansible modules NO LONGER require PyFOS.

### env ###

    Add library path to PYTHONPATH and ANSIBLE_LIBRARY variable

    bash example:

        if the repository is cloned under /home/myaccount/ansible-fos,

        export PYTHONPATH="/home/myaccount/ansible-fos/library/ansible/module_utils/storage/brocade"
        export ANSIBLE_LIBRARY="/home/myaccount/ansible-fos/library/ansible/modules/storage/brocade"


### Contact ###

    Automation.BSN@broadcom.com
