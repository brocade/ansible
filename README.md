# Brocade FOS FC Collection

The Brocade FOS collection consists of the latest versions of the FOS modules.

## Modules

- brocade_chassis - Brocade chassis Configuration
- brocade_facts - Brocade facts gathering
- brocade_fibrechannel_configuration_fabric - Brocade Fibre Channel fabric Configuration
- brocade_fibrechannel_configuration_port_configuration - Brocade Fibre Channel port Configuration
- brocade_fibrechannel_switch - Brocade Fibre Channel Switch Configuration
- brocade_interface_fibrechannel - Brocade Fibre Channel Port Configuration
- brocade_logging_audit - Brocade loggig audit Configuration
- brocade_logging_syslog_server - Brocade loggig syslog server Configuration
- brocade_security_ipfilter_policy - Brocade security ipfilter policy Configuration
- brocade_security_ipfilter_rule - Brocade security ipfilter rule Configuration
- brocade_security_user_config - Brocade security user config Configuration
- brocade_snmp_system - Brocade snmp system Configuration
- brocade_time_clock_server - Brocade time clock server Configuration
- brocade_time_time_zone - Brocade time time zone Configuration
- brocade_zoning_alias - Brocade Zoning Alias
- brocade_zoning_cfg - Brocade Zoning Cfgs
- brocade_zoning_default_zone - Brocade Zoning Default Zone Configuration
- brocade_zoning_zone - Brocade Zoning Zones

- brocade_singleton_obj - generic template object to handle singleton REST object. Tested with password object

## Utilities
- zoning_to_yaml.py - python script to output FOS zoning database in yaml to be used in zoning playbook (example, zoning_act.yml and zonedb.yml) using PyFOS

## Requirements

- Ansible 2.9 or later
- FOS running 8.2.1c or later

## Example Playbook
```yaml
- hosts: san_eng_zone_seed_san_a
  gather_facts: False
  collections:
    - daniel_chung_broadcom.fos

  vars:
    credential:
      fos_ip_addr: "{{fos_ip_addr}}"
      fos_user_name: admin
      fos_password: fibranne
      https: False
    aliases:
      - name: Host1
        members:
          - 11:22:33:44:55:66:77:88
      - name: Target1
        members:
          - 22:22:33:44:55:66:77:99      
      - name: Target2
        members:
          - 22:22:33:44:55:66:77:aa
      - name: Target3
        members:
          - 22:22:33:44:55:66:77:bb
    aliases_to_delete:
      - name: Target1
      - name: Target2
      - name: Target3
    zones:
      - name: NewZoneName
        members:
          - Host1
          - Target1
          - Target2
      - name: NewZoneName2
        members:
          - Host1
          - Target2
      - name: NewZoneNameP
        members:
          - 11:22:33:44:55:66:77:88
        principal_members:
          - 22:22:33:44:55:66:77:88
    zones_to_delete:
      - name: NewZoneNameP
      - name: NewZoneName2
    cfgs:
      - name: newcfg1
        members:
          - NewZoneName
          - NewZoneName2
      - name: newcfg2
        members:
          - NewZoneName
          - NewZoneName2
      - name: newcfg3
        members:
          - NewZoneName
          - NewZoneName2
    cfgs_to_delete:
      - name: newcfg2
      - name: newcfg3

  tasks:

  - name: Create aliases
    brocade_zoning_alias:
      credential: "{{credential}}"
      vfid: -1
      aliases: "{{aliases}}"
#      aliases_to_delete: "{{aliases_to_delete}}"

  - name: Create zones
    brocade_zoning_zone:
      credential: "{{credential}}"
      vfid: -1
      zones: "{{zones}}"
#      zones_to_delete: "{{zones_to_delete}}"

  - name: Create cfgs
    brocade_zoning_cfg:
      credential: "{{credential}}"
      vfid: -1
      cfgs: "{{cfgs}}"
#      cfgs_to_delete: "{{cfgs_to_delete}}"
      active_cfg: newcfg2

  - name: Default zoning
    brocade_zoning_default_zone:
      credential: "{{credential}}"
      vfid: -1
      default_zone_access: allaccess
```

## License

[BSD-2-Clause](https://directory.fsf.org/wiki?title=License:FreeBSD)

## Author

This collection was created in 2019 by Brocade Automation Team
