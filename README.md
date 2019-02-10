# Example Source Code for Blog Posts

This repository provides source code used to illustrate posts that I’ve written
for my blog at [https://nawilson.com/](https://nawilson.com/).

Unless otherwise documented, all example code in this repository is provided
under the terms of each of the following licenses:

* [The GNU General Public License version 2 (GPLv2)](LICENSE-GPLv2.txt)
* [The GNU Lesser General Public License version 2.1 (LGPLv2.1)](LICENSE-LGPLv2.1.txt)
* [The Apache License version 2.0](LICENSE-Apache-v2.0.txt)

The examples that are currently available include:

* [in-memory-cram-md5-handler-example](in-memory-cram-md5-handler-example) — An
  example of a SASL bind handler for the in-memory directory server included as
  part of the UnboundID LDAP SDK for Java. This example implements support for
  the CRAM-MD5 SASL mechanism. It wasn’t really written for a blog post, but
  rather as an illustration used to in answering a question asked on the
  [LDAP SDK’s discussion forum on
  SourceForge](https://sourceforge.net/p/ldap-sdk/discussion/1001257/thread/20bc11ee/).

* [ldap-join](ldap-join) — A sample program that demonstrates
  the use of the LDAP join control in the Ping Identity Directory Server and
  the UnboundID LDAP SDK for Java. It issues a search request to retrieve a
  user from the directory, where that search request includes a join request
  control that uses a DN join to retrieve entry for that user’s manager, and a
  nested join that also uses a reverse DN join to retrieve the entries for the
  manager’s direct reports.

* [multi-update](multi-update) — A sample program that demonstrates the use of
  the multi-update extended operation in the Ping Identity Directory Server and
  the UnboundID LDAP SDK for Java. It is basically a stripped-down version of
  the ldapmodify tool, except it can only read changes from an LDIF file, and
  all changes will be sent to the server in a multi-update operation.

* [password-policy-state-issues](password-policy-state-issues) — A sample
  program that demonstrates the use of the get password policy state issues
  control in the Ping Identity Directory Server and the UnboundID LDAP SDK for
  Java.

* [password-quality-requirements](password-quality-requirements) — A sample
  program that demonstrates how to use the get password quality extended
  operation and password validation details control in the Ping Identity
  Directory Server and the UnboundID LDAP SDK for Java. See the
  [Programmatically Retrieving Password Quality Requirements in the Ping
  Identity DirectoryServer](https://nawilson.com/2019/01/29/programmatically-retrieving-password-quality-requirements-in-the-ping-identity-directory-server/)
  blog post for more information.
