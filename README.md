Brocade Ansible reference example Modules and Playbooks
=======

This repository provides reference example Modules & Playbooks for Ansible
to manage Fibre Channel switches running FOS 8.2.1c & 9.0.0a. Tested with
Ansible 2.9.0 running Python 3.5.2. Also, Tested with AWX 13.0.0.

### Installation from Github.com ###

Step1: clone the repository

    HTTPS example:

        git clone https://github.com/brocade/ansible

Step2: Add library path ANSIBLE_LIBRARY variable

    bash example:

        if the repository is cloned under /home/myaccount/ansible,

        export ANSIBLE_LIBRARY="/home/myaccount/ansible/library"

Step3: update ansible.cfg to point to utils directory for module_utils

    Example available under ansible.cfg

### Tower/AWX ###

tower_awx branch is now merged to master. Since playbooks and ansible.cfg
are expected to be in the root directory for Tower/AWX, all playbooks
and ansible.cfg are moved from tasks directory to root directory.

#### Usage ####

Step 1: create a project within AWX and choose

```
SCN TYPE to Git
SCM URL to https://github.com/brocade/ansible.git
```

Step 2: create an inventory.

Step 3: add a host to the inventory. Use san_eng_zone_seed_san_a in the host name field.

Step 4: add the following to the variables for the host.

```
ansible_connection: local
fos_ip_addr: <IP address of FOS switch>
fos_user_name: admin
fos_password: <FOS password for admin>
https: <False/True/self>
```

These variables are used by playbooks available when choosing the project
created above to connect to FOS switch.

### Connection to FOS ###

Primary connection to FOS for playbooks is FOS REST connection. However, 
Some playbook attributes use ssh connect to augment the fuctionality. When
those attributes are specified in the playbooks, be sure that the FOS switch
being used to connect is part of known hosts by where ansible-playbook is
being executed or where AWX job is being executed.

Here are the examples of attributes using ssh.

| Ansible module name | Attributes |
| --- | --- |
| brocade_chassis | telnet_timeout|
| brocade_fibrechannel_configuration_fabric | fabric_principal_enabled, fabric_principal_priority, in_order_delivery_enabled|
| brocade_fibrechannel_configuration_port_configuration | credit_recovery_mode|
| brocade_fibrechannel_switch | dynamic_load_sharing (pre 9.0 only)|
| brocade_security_user_config | account_enabled (pre 9.0 only)|
| brocade_snmp | host being set to 0.0.0.0 (pre 9.0 only)|

If host key check is to be turned off, ssh_hostkeymust field in credential
variable should be set to false. Here is an example of how that can be done
by defining credential variable in extra variables section for AWX job template.


```
credential:
  fos_ip_addr: "{{fos_ip_addr}}"
  fos_user_name: "{{fos_user_name}}"
  fos_password: "{{fos_password}}"
  https: "{{fos_https}}"
  ssh_hostkeymust: False
```

### How to create playbooks ###

When creating Zoning playbooks, Zoning specific modules are used. This is to
hide some of the Zoning specific operational complexities that would otherwise
be exposed if using generic templates. However, most other REST FOS objects
can be addressed by common template modules: brocade_single_obj and brocade_list_obj.

#### Zoning ####

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

Here is an example of a simple playbook of Alias to create Host1 Alias with two
members and Target2 Alias with one member.

```
  - name: Create aliases
    brocade_zoning_alias:
      credential:
        fos_ip_addr: 10.10.10.10
        fos_user_name: admin
        fos_password: password
        https: False
      vfid: -1
      aliases:
        - name: Host1
          members:
            - aa:11:11:11:11:11:11:11
            - aa:22:22:22:22:22:22:22
        - name: Target2
          members:
            - aa:44:44:44:44:44:44:44
```

Alias, Zone, or CFG entry is deleted only if aliases_to_delete, zones_to_delete
or cfgs_to_delete variable is provided with a list of Alises, Zones or CFGs to delete.

Here is an example of a simple playbook of Alias to delete Host1 and Target2.

```
  - name: Delete aliases
    brocade_zoning_alias:
      credential:
        fos_ip_addr: 10.10.10.10
        fos_user_name: admin
        fos_password: password
        https: False
      vfid: -1
      aliases_to_delete:
        - name: Host1
        - name: Target2
```

Please refer to tasks/zoning_zone_delete.yml for additional reference.

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

If interested in copying an existing Alias, Zone, or CFG to a new object,
brocade_zoning_copy module is used. If any changes are detected in the Zoning
object - for example, new member is added to a Zone - being copied from,
the difference is newly applied to the destination object - i.e. the
added member is added to the destination Zone if already created.

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

#### Yang module/object specific Ansible modules ####

Here are the list of additional Ansible modules beyond Zoning. These modules
typically take a dictionary or a list of dictionary. The dictionary contains
attributes matching Yang REST leaf definitions. However, Ansible variables
require underscore while hyphen is used in Yang REST leaf definitions. So, the attributes
within the dictionary should match Yang REST leaf definition while replacing
hyphen with underscore. i.e. my-leaf-name in Yang REST is converted to my_leaf_name
within Ansible playbook.

| Ansible module name | Description |
| --- | --- |
| brocade_chassis.py | update chassis attributes |
| brocade_facts.py | retrieve facts for specified areas|
| brocade_fibrechannel_configuration_fabric.py | update fabric configuration |
| brocade_fibrechannel_configuration_port_configuration.py | update port configuration |
| brocade_fibrechannel_switch.py | update switch configuration |
| brocade_interface_fibrechannel.py | update FC port configuration |
| brocade_logging_audit.py | update audit configuration |
| brocade_logging_syslog_server.py | update syslog server configuration |
| brocade_maps_maps_config.py | update MAPS configuration |
| brocade_operation_show_status.py | show status on operations initiated |
| brocade_operation_supportsave.py | initiate supportsave operation |
| brocade_security_ipfilter_policy.py | update ip filter policy |
| brocade_security_ipfilter_rule.py | update ip filter rule |
| brocade_security_password.py | update password. Passwords are given in clear text |
| brocade_security_security_certificate_action.py | import/export CSR/certificate |
| brocade_security_security_certificate_generate.py | generate CSR/certificate |
| brocade_security_user_config.py | update login accounts |
| brocade_snmp_system.py | update snmp system attributes |
| brocade_snmp_v1_account.py | update snmp v1 account |
| brocade_snmp_v1_trap.py | update snmp v1 trap |
| brocade_snmp_v3_account.py | update snmp v3 account |
| brocade_snmp_v3_trap.py | update snmp v3 trap |
| brocade_time_clock_server.py | update clock server configuration |
| brocade_time_time_zone.py | update time zone |

#### Template based Ansible modules ####

REST Yang objects that have yet been addressed by Yang module/object specific
Ansible modules, template based Ansible modules can be used to address them
temporarily. Although template based Ansible modules should generally work
well with most REST Yang modules, some RET Yang objects specific may not be
handled properly. So, it is recommended that Yang module/object specific
Ansible modules be used preferably.

##### Singleton object #####

A singleton object refers to a FOS REST object that is only one of the kind on FOS switch.
Yang definition of container is used to define this type of object. Using the Yang definition
and brocade_singleton_obj module, playbooks can be created to update the object.

All the Yang REST FOS models are published in github.com/brocade/yang.

For example, brocade-chassis module contains an object named chassis. And chassis object
contains a string type leaf named chassis-user-friendly-name, amoung other attributes.

```
module brocade-chassis {
    container brocade-chassis {
        container chassis {
            leaf chassis-user-friendly-name {
            }
        }
    }
}
```

To create a playbook to set chassis-user-friendly-name to XYZ is created by:

1) use brocade_singleton_obj module
2) provide the module_name to match the Yang REST FOS module name - brocade-chassis or brocade_chassis. "-" and "_" are interchangable as module_name.
3) provide the obj_name to match the Yang REST FOS object name - chassis. As with module_name, "-" and "_" are interchangable as obj_name.
4) provide leaf entry within attributes. Only one - chassis-user-friendly-name - is being referenced for the moment. Since Ansible variable should not contain "-", they are placed by "-".

```
  - name: chassis configuration
    brocade_singleton_obj:
      credential:
        fos_ip_addr: 10.10.10.10
        fos_user_name: admin
        fos_password: password
        https: False
      vfid: -1
      module_name: "brocade_chassis"
      obj_name: "chassis"
      attributes:
        chassis_user_friendly_name: XYZ
```

Playing the above playbook to set the chassis-user-friendly-name to XYZ if different or 
return no change if already set to XYZ. 

Although the module should apply to all objects in general, the following are the list
of modules and objects that have been verified based on the playbooks under tasks
directory

| module name | object name |
| --- | --- |
| brocade_chassis | chassis |
| brocade_fibrechannel_configuration | fabric |
| brocade_fibrechannel_configuration | port_configuration |
| brocade_logging | audit |
| brocade-maps | maps-config |
| brocade-security | password |
| brocade-snmp | system |
| brocade_time | clock_server |
| brocade_time | time_zone |

##### List object #####

A list object refers to a FOS REST object that can contain multiple entries on FOS switch.
Yang definition of list is used to define this type of object. Using the Yang definition
and brocade_list_obj module, playbooks can be created to create, update, or delete the object.

All the Yang REST FOS models are published in github.com/brocade/yang.

For example, brocade-snmp module contains an object named v1-account. And v1-account object
contains a key named index and a string type leaf named community-name, among other attributes.

```
module brocade-snmp {
    container brocade-snmp {
        list v1-account {
            key "index";
            leaf index {
            }
            leaf community-name {
            }
        }
    }
}
```

To create a playbook to set community-name to XYZ for an entry with index of 1,
and ZYX for index of 2:

1) use brocade_list_obj module
2) provide the module_name to match the Yang REST FOS module name - brocade-snmp or brocade_snmp. "-" and "_" are interchangable as module_name.
3) provide the list_name to match the Yang REST FOS object name - v1-account or v1_account. As with module_name, "-" and "_" are interchangable as list_name.
4) provide an array within entries. Only key and community_string are being referenced for the moment. Since Ansible variable should not contain "-", they are placed by "-".
5) if the array contains all the entries, all_entries variable can be left out or set to True. If so, entries in playbook but not in FOS are added, entries in both playbook and FOS are updated if different, and entries not in playbook but in FOS are deleted. If the array contains only subset of all entries, only addition and update are performed.

```
  - name: snmp configuration
    brocade_list_obj:
      credential:
        fos_ip_addr: 10.10.10.10
        fos_user_name: admin
        fos_password: password
        https: False
      vfid: -1
      module_name: "brocade_snmp"
      obj_name: "v1_account"
      all_entries: False
      entries:
        - index: 1 
          community_name: XYZ
        - index: 2
          community_name: ZYX
```

Playing the above playbook to set the community name for two entries. Rest of the entries
already exist on FOS are untouched.

Although the module should apply to all objects in general, the following are the list
of modules and objects that have been verified based on the playbooks under tasks
directory

| module name | list name |
| --- | --- |
| brocade_fibrechannel_switch | fibrechannel_switch |
| brocade-interface | fibrechannel |
| brocade_logging | syslog_server |
| brocade-name-server | fibrechannel-name-server |
| brocade-snmp | v1-account |
| brocade-snmp | v1-trap |
| brocade-snmp | v3-account |
| brocade-snmp | v3-trap |
| brocade_security | user_config |
| brocade-security | ipfilter-rule |

### Contact ###

    Automation.BSN@broadcom.com
