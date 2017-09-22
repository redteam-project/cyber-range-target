cyber-test-range-target
=========

This role endeavors to simplify building a host  for a cyber-test range.

Requirements
------------

Ansible 2.4

Role Variables
--------------

```
---
# defaults file for cyber-test-range-target
# Which CVE's should be tested on a host
cves_to_test: []
```

Dependencies
------------

There are no known dependencies.

Example Playbook
----------------
The following example playbook would ensure that Bash prone to shell shock is available on the host.

```yaml
---
- hosts: webservers
  remote_user: admin
  become: true
  roles:
    - fedoraredteam.cyber-test-range-target
  vars:
    cves_to_test:
    - CVE-2014-6271
```

License
-------

GPLv3
