## Repository Information 
 Repo URL: https://github.com/brocade/ansible

Brocade Ansible reference example Modules and Playbooks - Prototype code
=======

This repository provides reference example Modules & Playbooks for Ansible
to manage Fibre Channel switches running FOS 8.2.x.

### dependency ###

    Paramiko and xmltodict. BSN Ansible modules NO LONGER require PyFOS.

### env ###

    Add library path to PYTHONPATH and ANSIBLE_LIBRARY variable

    bash example:

        if the repository is cloned under /home/myaccount/ansible,

        export PYTHONPATH="/home/myaccount/ansible/library/ansible/module_utils/storage/brocade"
        export ANSIBLE_LIBRARY="/home/myaccount/ansible/library/ansible/modules/storage/brocade"

###	Contributing ###

Contributions to this project require the submission of a Contributor Assignment
Agreement (“CAA”). The CAA transfers the copyright to your contribution from you 
(or your employer) to Broadcom, and in return Broadcom grants back a license to use 
your Contribution. This ensures Broadcom has the flexibility to license the 
project under an appropriate license. For more information on contributing 
see CONTRIBUTING.md.

### Contact ###

    Automation.BSN@broadcom.com
