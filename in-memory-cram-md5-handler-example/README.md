# in-memory-cram-md5-handler-example

This repository provides source code for a sample InMemorySASLBindHandler for
the UnboundID LDAP SDK for Java's in-memory directory server.  This SASL bind
handler implements support for the CRAM-MD5 SASL mechanism.  This mechanism is
obsolete and should not be used for real-world authentication (which is why
it's not being included in the LDAP SDK itself), but the code here can be used
as a starting point for demonstrating how to create a custom
InMemorySASLBindHandler implementation for other, more desirable SASL
mechanisms (especially those that rely on the javax.security.sasl.SaslServer
class to perform the core processing).

Also see the com.unboundid.ldap.listener.PLAINBindHandler class for an example
of an InMemorySASLBindHandler that does not make use of the SaslServer
framework.

Code in this repository is available under three licenses:

* The GNU General Public License version 2.0 (GPLv2).  See the
  [LICENSE-GPLv2.txt](LICENSE-GPLv2.txt) file for this license.

* The GNU Lesser General Public License version 2.1 (LGPLv2.1).  See the
  [LICENSE-LGPLv2.1.txt](LICENSE-LGPLv2.1.txt) file for this license.

* The Apache License version 2.0.  See the
  [LICENSE-Apache-v2.0.txt](LICENSE-Apache-v2.0.txt) file for this license.
