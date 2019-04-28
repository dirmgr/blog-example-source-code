# Name With entryUUID Request Control Example

This repository provides source code for a sample program that demonstrates the
use of the name with entryUUID request control in the Ping Identity Directory
Server and the UnboundID LDAP SDK for Java. It includes this control in an add
request, and then uses the post-read response control in the add result to
determine the actual DN that was given to the entry.

The [UnboundID LDAP SDK for Java](https://github.com/pingidentity/ldapsdk) is
the only dependency for this example.

Code in this repository is available under three licenses:

* The GNU General Public License version 2.0 (GPLv2).  See the
  [LICENSE-GPLv2.txt](LICENSE-GPLv2.txt) file for this license.

* The GNU Lesser General Public License version 2.1 (LGPLv2.1).  See the
  [LICENSE-LGPLv2.1.txt](LICENSE-LGPLv2.1.txt) file for this license.

* The Apache License version 2.0.  See the
  [LICENSE-Apache-v2.0.txt](LICENSE-Apache-v2.0.txt) file for this license.

## EXAMPLE

The following is an example of the output provided by this program:

    The server presented the following certificate chain:

         Subject: CN=ds.example.com,O=Ping Identity Self-Signed Certificate
         Valid From: Saturday, April 27, 2019 at 11:11:58 AM CDT
         Valid Until: Saturday, April 23, 2039 at 11:11:58 AM CDT
         SHA-1 Fingerprint: 41:5f:72:4a:e0:d0:22:18:3e:59:90:6f:65:fc:fe:34:f1:39:84:68
         256-bit SHA-2 Fingerprint: 54:d5:58:07:bd:af:8b:b4:19:8e:03:a3:c5:14:0d:2a:e6:1e:c2:3a:29:6c:17:5f:5f:61:97:1d:31:3d:2b:ac

    WARNING:  The certificate is self-signed.

    Do you wish to trust this certificate?  Enter 'y' or 'n': y
    Successfully established a secure connection to ds.example.com:636

    Successfully authenticated as user cn=Name With entryUUID Example,ou=Applications,dc=example,dc=com

    The server root DSE advertises support for the name with entryUUID request control.

    Sending add request:
    dn: replaceWithEntryUUID=replaceWithEntryUUID,ou=People,dc=example,dc=com
    control: 1.3.6.1.4.1.30221.2.5.44 true
    changetype: add
    objectClass: top
    objectClass: person
    objectClass: organizationalPerson
    objectClass: inetOrgPerson
    uid: test.user
    givenName: Test
    sn: User
    cn: Test User
    userPassword: testUserPassword


    Successfully added the test entry, and its resulting DN was 'entryUUID=4869eea6-90bf-45bf-9fcb-eac096564bc8,ou=People,dc=example,dc=com'.

    Full content of the resulting entry:
    dn: entryUUID=4869eea6-90bf-45bf-9fcb-eac096564bc8,ou=People,dc=example,dc=com
    objectClass: top
    objectClass: person
    objectClass: organizationalPerson
    objectClass: inetOrgPerson
    sn: User
    cn: Test User
    givenName: Test
    userPassword: {SSHA256}Zr1sHf97PP2P2wBTigctjmoyHX1n6lWmZ5uK9u10ITEMOMWY7qujLg==
    uid: test.user
    createTimestamp: 20190428202551.941Z
    pwdChangedTime: 20190428202551.941Z
    creatorsName: cn=Name With entryUUID Example,ou=Applications,dc=example,dc=com
    modifyTimestamp: 20190428202551.941Z
    modifiersName: cn=Name With entryUUID Example,ou=Applications,dc=example,dc=com
    entryUUID: 4869eea6-90bf-45bf-9fcb-eac096564bc8
    ds-entry-checksum: 4447480622
    subschemaSubentry: cn=schema
