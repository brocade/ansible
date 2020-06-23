Brocade Ansible reference example Modules and Playbooks - Tower/AWX structure
=======

This branch - tower_awx - in this repository provides reference example Modules
& Playbooks for Ansible to manage Fibre Channel switches running FOS 8.2.1c.
Tested with Ansible 2.9.0 running Python 3.5.2.

Ansible Tower/AWX expects project structure to contain playbooks and customed
ansible.cfg to be located within root directory. These files are moved moved
from tasks directory in the mater branch to the root diretory in tower_awx
branch. Tested with AWN 13.0.0.

### Usage ###

When creating project within AWX, choose

SCN TYPE to Git
SCM URL to https://github.com/brocade/ansible.git
SCM BRANCH/TAG/COMMIT to tower_awx

When creating inventory, add to variables

fos_ip_addr: xx.xx.xx.xx

This variable is used by playbooks available when choosing the project
created above.

### Contact ###

    Automation.BSN@broadcom.com
