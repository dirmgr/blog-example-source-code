# Example Source Code for Blog Posts

This repository provides source code used to illustrate posts that I’ve written for my blog at [https://nawilson.com/](https://nawilson.com/).

Unless otherwise documented, all example code in this repository is provided under the terms of each of the following licenses:

* [The GNU General Public License version 2 (GPLv2)](LICENSE-GPLv2.txt)
* [The GNU Lesser General Public License version 2.1 (LGPLv2.1)](LICENSE-LGPLv2.1.txt)
* [The Apache License version 2.0](LICENSE-Apache-v2.0.txt)

The examples that are currently available include:

* [password-quality-requirements](password-quality-requirements) — A sample program that demonstrates how to use the get password quality extended operation and password validation details control in the Ping Identity Directory Server. See the [Programmatically Retrieving Password Quality Requirements in the Ping Identity Directory Server](https://nawilson.com/2019/01/29/programmatically-retrieving-password-quality-requirements-in-the-ping-identity-directory-server/) blog post for more information.

* [in-memory-cram-md5-handler-example](in-memory-cram-md5-handler-example) — An example of a SASL bind handler for the in-memory directory server included as part of the UnboundID LDAP SDK for Java. This example implements support for the CRAM-MD5 SASL mechanism. It wasn’t really written for a blog post, but rather as an illustration used to in answering a question asked on the [LDAP SDK’s discussion forum on SourceForge](https://sourceforge.net/p/ldap-sdk/discussion/1001257/thread/20bc11ee/).
