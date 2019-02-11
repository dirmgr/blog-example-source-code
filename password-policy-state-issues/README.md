# Get Password Policy State Issues Control Example

This repository provides source code for a sample program that demonstrates the
use of the get password policy state issues control in the Ping Identity
Directory Server and the UnboundID LDAP SDK for Java. It first binds as an
application account with the permit-get-password-policy-state-issues privilege
and the ability to use both the get password policy state issues and the retain
identity controls, and will then use those controls while attempting to
authenticate a specified user. If the authentication fails, then the reason for
that failure will be displayed to the user. In any case, any password policy
state errors, warnings, and notices included in the get password policy state
issues response control will be displayed.

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

The following is an example of using this program when the wrong password was
provided for a user whose password has recently been reset by an administrator:

    Enter the directory server address: ds.example.com
    Enter the directory server port: 636
    Do you want the connection to be secured with TLS? yes
    The server presented the following certificate chain:

         Subject: CN=ds.example.com,O=Ping Identity Self-Signed Certificate
         Valid From: Friday, February 8, 2019 at 03:27:24 PM CST
         Valid Until: Friday, February 4, 2039 at 03:27:24 PM CST
         SHA-1 Fingerprint: c7:c1:b9:c4:e0:e2:cb:5d:fd:02:ed:2b:ee:7e:60:4f:8c:36:ed:ef
         256-bit SHA-2 Fingerprint: 42:86:4d:75:cf:35:51:f8:9b:93:8e:af:ac:d8:9d:38:4f:b6:bc:2d:58:61:1e:64:86:44:fb:26:8f:6e:3b:96

    WARNING:  The certificate is self-signed.

    Do you wish to trust this certificate?  Enter 'y' or 'n': yes

    The directory server appears to support both the get password policy state issues request control and the retain identity request control.

    Enter the DN of an account that has permission to use the get password policy state issues and retain identity request controls: cn=Demo Authenticator,ou=Applications,dc=example,dc=com
    Enter the password for 'cn=Demo Authenticator,ou=Applications,dc=example,dc=com':
    Successfully authenticated as cn=Demo Authenticator,ou=Applications,dc=example,dc=com

    Enter the DN of the user to attempt to authenticate while using the get password policy state issues request control: uid=jdoe,ou=People,dc=example,dc=com
    Enter the password for 'uid=jdoe,ou=People,dc=example,dc=com:
    The attempt to bind as 'uid=jdoe,ou=People,dc=example,dc=com' failed:
    LDAP Result Code: 49 (invalid credentials)

    Authentication Failure Reason Name: invalid-credentials
    Authentication Failure Reason Type: 9
    Authentication Failure Reason Message: The provided password does not match any password in the user's entry.  The account will be locked after 9 more failed attempt(s)

    Usability Error Name: must-change-password
    Usability Error Type: 11
    Usability Error Message: The password was reset by an administrator and must be changed before it can be used to request any operations.  The account will be locked if the password is not changed by 20190210224219.189Z (23 hours, 57 minutes, 39 seconds from now)

    Usability Warning Name: password-expiring
    Usability Warning Type: 2
    Usability Warning Message: The password will expire at 20190210224219.189Z (23 hours, 57 minutes, 39 seconds from now)

    Usability Warning Name: outstanding-bind-failures
    Usability Warning Type: 3
    Usability Warning Message: The account has experienced 1 authentication failure(s) since the last successful bind.  The account will be locked after 9 more failure(s)

    There are no password policy state notices.
