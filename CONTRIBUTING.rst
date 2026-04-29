============
Contribution
============

Contributors must sign and submit a CAA before a contribution can be
accepted. Two CAAs are available, one for individual contributions and
one for contributions made on behalf of an entity, e.g., an employer.
Select the appropriate link below to electronically execute a CAA.

Contributor Assignment Agreement (“CAA”)
========================================

CAA - Individual:
https://na3.docusign.net/Member/PowerFormSigning.aspx?PowerFormId=7af19c0f-ae97-4b56-b950-fc4796860c79

CAA - Entity:
https://na3.docusign.net/Member/PowerFormSigning.aspx?PowerFormId=f657df18-ed64-4c51-a8f2-618bbd17d355

Development Setup
=================

Install the dependencies needed for development:

.. code-block:: bash

   pip install -r requirements-dev.txt

Running Code Sanity Checks
==========================

Before submitting a contribution, run sanity checks to validate your
changes:

.. code-block:: bash

   # Validate the entire repository
   python tests/sanity/code_sanity.py

   # Validate specific files or directories
   python tests/sanity/code_sanity.py --path path/to/file.py

For full usage details run ``python tests/sanity/code_sanity.py -h``.

Documentation Conventions
=========================

When adding or updating examples, playbooks, and documentation, please ensure that no Personal Identifiable Information (PII) or real network data is included. Use the following standard placeholders:

* **IP Addresses**: Use standard TEST-NET documentation blocks (RFC 5737).
  * Switches/Hosts: `198.51.100.x` (e.g., `198.51.100.1`, `198.51.100.2`)
  * Servers (DNS, NTP, Syslog, etc.): `203.0.113.x` (e.g., `203.0.113.10`)
* **Port WWNs (PWWN)**: Use dummy values starting with `aa:bb:cc:dd:ee:ff:11:11` and increment the last octet as needed.
* **Domain Names**: Use `example.com`, `example.net`, or `example.org`.
* **Emails**: Use `sender@example.com` or `receiver@example.com`.
* **Credentials**:
  * Usernames: `user_name`
  * Passwords: `user_password`
  * Vault Passwords: `vault_password`
* **Locations**: Use generic terms like `Data Center 1` or `Data Center 2`.
* **Zone/Config Names**: Use generic names like `zone_1`, `cfg_1`, `alias_host_1`.

Building Documentation
======================

See `docs/documentation.rst <docs/documentation.rst>`_ for instructions on
building the Sphinx documentation.
