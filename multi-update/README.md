# Multi-Update Extended Operation Example

This repository provides source code for a sample program that demonstrates the
use of the multi-update extended operation in the Ping Identity Directory
Server and the UnboundID LDAP SDK for Java. It is basically a stripped-down
version of the ldapmodify tool, except it can only read changes from an LDIF
file, and all changes will be sent to the server in a multi-update operation.

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

The following is an example of using this program in an attempt to atomically
apply a set of changes when one of those changes could not be processed:

    $ java -cp ./unboundid-ldapsdk.jar com.dirmgr.example.multiupdate.MultiUpdateLDAPModify --hostname ds.example.com --port 636 --useSSL --bindDN "cn=Directory Manager" --ldifFile changes.ldif --errorBehavior atomic
    Enter the bind password:

    The server presented the following certificate chain:

         Subject: CN=ds.example.com,O=Ping Identity Self-Signed Certificate
         Valid From: Friday, February 8, 2019 at 03:27:24 PM CST
         Valid Until: Friday, February 4, 2039 at 03:27:24 PM CST
         SHA-1 Fingerprint: c7:c1:b9:c4:e0:e2:cb:5d:fd:02:ed:2b:ee:7e:60:4f:8c:36:ed:ef
         256-bit SHA-2 Fingerprint: 42:86:4d:75:cf:35:51:f8:9b:93:8e:af:ac:d8:9d:38:4f:b6:bc:2d:58:61:1e:64:86:44:fb:26:8f:6e:3b:96

    WARNING:  The certificate is self-signed.

    Do you wish to trust this certificate?  Enter 'y' or 'n': yes
    Multi-Update Result Code: 0 (success)
    Multi-Update Diagnostic Message: 0 (success)
    None of the changes were successfully applied.
    Failed to add dc=example,dc=com
    Result Code: 118 (canceled)
    Diagnostic Message: Although this update initially succeeded, it was reverted because the multi-update request had an error behavior of 'ATOMIC' and a failure was encountered while processing a subsequent update in the request

    Failed to add ou=People,dc=example,dc=com
    Result Code: 118 (canceled)
    Diagnostic Message: Although this update initially succeeded, it was reverted because the multi-update request had an error behavior of 'ATOMIC' and a failure was encountered while processing a subsequent update in the request

    Failed to add uid=jdoe,ou=People,dc=example,dc=com
    Result Code: 118 (canceled)
    Diagnostic Message: Although this update initially succeeded, it was reverted because the multi-update request had an error behavior of 'ATOMIC' and a failure was encountered while processing a subsequent update in the request

    Failed to modify uid=jdoe,ou=People,dc=example,dc=com
    Result Code: 16 (no such attribute)
    Diagnostic Message: Entry uid=jdoe,ou=People,dc=example,dc=com cannot be modified because an attempt was made to remove one or more values from attribute description but this attribute is not present in the entry

    Failed to rename uid=jdoe,ou=People,dc=example,dc=com
    Result Code: 118 (canceled)
    Diagnostic Message: This update was not attempted because the multi-update request had an error behavior of 'ATOMIC' and a failure was encountered while processing a previous update in the request
