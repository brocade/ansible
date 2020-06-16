Brocade Ansible reference example Modules and Playbooks
=======

This repository provides reference example Modules & Playbooks for Ansible
to manage Fibre Channel switches running FOS 8.2.1c. Tested with Ansible
2.9.0 running Python 3.5.2.

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

### How to create plabyooks ###

## Zoning ##

Using brocade_zoning_alias, brocade_zoning_zone, and brocade_zoning_cfg modules,
playbooks can be created to update Alias, Zone, or CFG in FOS Zoning database
respectively.

When adding Alias, Zone or CFG, each module takes a list of entries. Each entry
contains a name and a list of members. brocade_zoning_zone module can take
principal_members in addition to members if you are interested in creating peer
zones. During addition, entries are considered additive to the existing FOS
Zoning database. In other word, if a playbook contains Aliases AAA and BBB and FOS
Zoning database contained BBB and CCC before the execution of the playbook,
the result of the playbook will contain Aliases AAA, BBB, and CCC. CCC is not
removed even though it is not mentioned in the playbook.

Alias, Zone, or CFG entry is deleted only if aliases_to_delete, zones_to_delete
or cfgs_to_delete variable is provided with a list of Alises, Zones or CFGs to delete.
Please refer to tasks/zoning_zone_delete.yml for reference.

Alias, Zone, or CFG entry addition and deletion are mutually exclusive.

Members to existing Alias, Zone or CFG entries are updated during a play if
difference exists between a playbook and the existing FOS Zoning database.
By default, members or principal_members are thought to be a full list and NOT additive.
Thus resulting play of FOS Zoning database will contain the members defined in the
playbook only. For example, if a playbook defines an Alias with members AAA and BBB
and the Alias in FOS Zoning database contained BBB and CCC before the execution of the playbook,
the result of the playbook will be an Alias with AAA and BBB. AAA was added and CCC
was deleted.

However, if optional members_add_only variable is set to True for the task,
the result of the previous playbook will be AAA, BBB, and CCC, where AAA is added and CCC remains.

Inversely, optional members_remove_only variable is set to True to specify removal of specific
Alias, Zone, or CFG members.

Please refer to tasks/zoning_zone_add.yml for default behavior reference,
tasks/zoning_zone_members_add_only.yml for members_add_only
reference and tasks/zoning_zone_members_remove_only.yml for members_remove_only
reference.

During execution, each module will update the define configuration and either
save or enable CFG depending on if a CFG is already active on FOS. If any
error is encountered, the changes are aborted and the FOS Zoning database will
revert back to pre-task state.

An optional active_cfg variable is only applicable to brocade_zoning_cfg module.
The variable is used to specify a CFG to be enabled.

Since Zoning modules are additive for entries by default, it is not necessary
that the full Zoning database is refered in the playbooks. However, maintaining
a full database in a playbook may be beneficial for certain use cases. To
help, PyFOS based zoning_to_yml.py is provided to dump the existing FOS Zoning
database in yml format. The screen output can be saved to a file and referenced
in playbooks. Please refer to github.com/brocade/pyfos for PyFOS details and
tasks/zonedb.yml and tasks/zoning_act.yml for reference.

### Contact ###

    Automation.BSN@broadcom.com
