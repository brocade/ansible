Brocade Ansible reference example Modules and Playbooks - Tower/AWX structure
=======

This branch - tower_awx - in this brocade/ansible repository provides reference
example Modules & Playbooks for Ansible to manage Fibre Channel switches running
FOS 8.2.1c.

Ansible Tower/AWX expects referenced git SCM projects to contain playbooks and
custom ansible.cfg to be located within the root directory of the repo. Therefore,
these files are moved from their location within tasks directory in the
mater branch to the root diretory in tower_awx branch.

Tested with AWX 13.0.0.

### Usage ###

When creating a project within AWX, choose

```
SCN TYPE to Git
SCM URL to https://github.com/brocade/ansible.git
SCM BRANCH/TAG/COMMIT to tower_awx
```

When creating inventory, add to variables

```
fos_ip_addr: <IP address of FOS switch>
fos_login: admin
fos_password: <FOS password for admin>
```

This variable is used by playbooks available when choosing the project
created above to connect to FOS switch.

### Contact ###

    Automation.BSN@broadcom.com
