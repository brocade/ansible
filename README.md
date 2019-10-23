Brocade Ansible reference example Modules and Playbooks
=======

This repository provides reference example Modules & Playbooks for Ansible
to manage Fibre Channel switches running FOS 8.2.1c. Tested with Ansible
2.7.5 running Python 3.5.2.

### Installation ###

Step1: clone the repository

    HTTPS example:

        git clone https://github.com/brocade/ansible

Step2: Add library path ANSIBLE_LIBRARY variable

    bash example:

        if the repository is cloned under /home/myaccount/ansible,

        export ANSIBLE_LIBRARY="/home/myaccount/ansible/library"

Step3: update ansible.cfg to point to utils directory for module_utils

    Example available under tasks/ansible.cfg

### Contact ###

    Automation.BSN@broadcom.com
