Brocade Ansible reference example Modules and Playbooks
=======

This repository provides reference example Modules & Playbooks for Ansible
to manage Fibre Channel switches running FOS 8.2.x. Tested with Ansible
2.7.5 running Python 3.5.2.

### Installation ###

Step1: clone the repository

    HTTPS example:

        git clone https://github.com/brocade/ansible

Step2: Add library path to PYTHONPATH and ANSIBLE_LIBRARY variable

    bash example:

        if the repository is cloned under /home/myaccount/ansible,

        export PYTHONPATH="/home/myaccount/ansible/library/ansible/module_utils/storage/brocade"
        export ANSIBLE_LIBRARY="/home/myaccount/ansible/library/ansible/modules/storage/brocade"


### Contact ###

    Automation.BSN@broadcom.com
