/*
 * Copyright 2019 Neil A. Wilson
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2019 Neil A. Wilson
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License (GPLv2 only)
 * or the terms of the GNU Lesser General Public License (LGPLv2.1 only)
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses>.
 */
/*
 * Copyright 2019 Neil A. Wilson
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.dirmgr.example.namewithentryuuid;



import javax.net.ssl.SSLSocketFactory;

import com.unboundid.ldap.sdk.AddRequest;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.RootDSE;
import com.unboundid.ldap.sdk.SearchRequest;
import com.unboundid.ldap.sdk.controls.PostReadResponseControl;
import com.unboundid.ldap.sdk.unboundidds.controls.
            NameWithEntryUUIDRequestControl;
import com.unboundid.ldif.LDIFException;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ssl.AggregateTrustManager;
import com.unboundid.util.ssl.JVMDefaultTrustManager;
import com.unboundid.util.ssl.PromptTrustManager;
import com.unboundid.util.ssl.SSLUtil;



/**
 * This class demonstrates the use of the name with entryUUID request control in
 * the Ping Identity Directory Server and the UnboundID LDAP SDK for Java.  It
 * adds an entry to the server using this control and uses the post-read
 * response control to determine the actual DN that the server used for the
 * entry.
 */
public class AddEntryNamedWithUUID
{
  /**
   * Runs this program with the provided set of arguments.
   *
   * @param  args  The command-line arguments provided to this program.  This
   *               program obtains all of the necessary information
   *               interactively and therefore does not require any command-line
   *               arguments.
   */
  public static void main(final String... args)
  {
    // Establish a secure, authenticated connection to the server.
    try (LDAPConnection connection = getLDAPConnection())
    {
      // Verify that the server root DSE claims to support the name with
      // entryUUID request control.
      System.out.println();
      checkRootDSE(connection);


      // Add a test entry using the name with entryUUID request control and
      // get the actual DN for the resulting entry.
      System.out.println();
      final String actualDN = addEntryNamedWithEntryUUID(connection, new Entry(
           "dn: replaceWithEntryUUID=replaceWithEntryUUID," +
                "ou=People,dc=example,dc=com",
           "objectClass: top",
           "objectClass: person",
           "objectClass: organizationalPerson",
           "objectClass: inetOrgPerson",
           "uid: test.user",
           "givenName: Test",
           "sn: User",
           "cn: Test User",
           "userPassword: testUserPassword"));
      System.out.println("Successfully added the test entry, and its " +
           "resulting DN was '" + actualDN + "'.");

      System.out.println();
      displayFullEntry(connection, actualDN);
    }
    catch (final LDAPException e)
    {
      System.err.println(StaticUtils.getExceptionMessage(e));
      System.exit(e.getResultCode().intValue());
    }
    catch (final LDIFException e)
    {
      System.err.println(StaticUtils.getExceptionMessage(e));
      System.exit(ResultCode.LOCAL_ERROR_INT_VALUE);
    }
  }



  /**
   * Establishes an authenticated connection to the directroy server.
   *
   * @return  The connection that was established.
   *
   * @throws  LDAPException  If a problem is encountered while establishing or
   *                         authenticating the connection.
   */
  private static LDAPConnection getLDAPConnection()
          throws LDAPException
  {
    // Create an SSL socket factory that will automatically accept the
    // certificate if it was issued by an authority that is included in the
    // JVM's default trust store, and will interactively prompt the user about
    // whether to accept the certificate if it's self-signed or uses some other
    // authority.
    final SSLSocketFactory sslSocketFactory;
    try
    {
      final SSLUtil sslUtil = new SSLUtil(new AggregateTrustManager(false,
           JVMDefaultTrustManager.getInstance(),
           new PromptTrustManager()));

      sslSocketFactory = sslUtil.createSSLSocketFactory();
    }
    catch (final Exception e)
    {
      throw new LDAPException(ResultCode.LOCAL_ERROR,
           "Unable to create an SSL socket factory:  " +
                StaticUtils.getExceptionMessage(e),
           e);
    }

    // Establish a secure connection to the Directory Server.
    final String serverAddress = "ds.example.com";
    final int serverPort = 636;
    final LDAPConnection connection = new LDAPConnection(sslSocketFactory,
         serverAddress, serverPort);
    System.out.println("Successfully established a secure connection to " +
         serverAddress + ":" + serverPort);
    System.out.println();

    // Authenticate to the server.  If the authentication fails, then make sure
    // the connection gets closed before propagating the exception to the
    // caller.
    boolean authenticationSucceeded = false;
    try
    {
      final String bindDN =
           "cn=Name With entryUUID Example,ou=Applications,dc=example,dc=com";
      final String bindPassword = "exampleUserPassword";
      connection.bind(bindDN, bindPassword);
      authenticationSucceeded = true;
      System.out.println("Successfully authenticated as user " + bindDN);
    }
    finally
    {
      if (! authenticationSucceeded)
      {
        connection.close();
      }
    }

    // Return the established and authenticated connection.
    return connection;
  }



  /**
   * Checks the directory server root DSe to ensure that it claims to support
   * the name with entryUUID request control.
   *
   * @param  connection  The connection to use to communicate with the directory
   *                     server.
   *
   * @throws  LDAPException  If an error occurs while tyring to retrieve the
   *                         root DSE, or if it does not claim to support the
   *                         name with entryUUID request control.
   */
  private static void checkRootDSE(final LDAPConnection connection)
           throws LDAPException
  {
    final RootDSE rootDSE;
    try
    {
      rootDSE = connection.getRootDSE();
      if (rootDSE == null)
      {
        // We couldn't retrieve the root DSE, which means that it might not
        /// be accessible to the authenticated user.  Print a warning and
        // return.
        System.err.println("WARNING:  Could not retrieve the root DSE to " +
             "verify whether it supports the name with entryUUID request " +
             "control.  Proceeeding under the assumption that it does.");
        return;
      }
    }
    catch (final LDAPException e)
    {
      throw new LDAPException(e.getResultCode(),
           "An error occurred while trying to retrieve the server root DSE " +
                "to verify that it supports the name with entryUUID " +
                "request control:  " + StaticUtils.getExceptionMessage(e),
           e);
    }

    if (rootDSE.supportsControl(
         NameWithEntryUUIDRequestControl.NAME_WITH_ENTRY_UUID_REQUEST_OID))
    {
      System.out.println("The server root DSE advertises support for the " +
           "name with entryUUID request control.");
    }
    else
    {
      throw new LDAPException(ResultCode.CONTROL_NOT_FOUND,
           "The server root DSE does not claim to support the name with " +
                "entryUUID request control.");
    }
  }



  /**
   * Adds the provided entry to the server, using the name with entryUUID
   * request control to cause its RDN to be replaced with one containing the
   * entryUUID attribute.
   *
   * @param  connection  The connection to use to communicate with the directory
   *                     server.
   * @param  entry       The entry to be added.  The current RDN will be
   *                     replaced with one containing the resulting entry's
   *                     entryUUID, so the RDN can be anything.  However, the DN
   *                     must be located in the desired portion of the DIT (that
   *                     is, the parent DN for the provided entry will be the
   *                     parent entry for the entry that is actually created).
   *
   * @return  The DN that the server assigned to the entry that was created.
   *
   * @throws  LDAPException  If a problem occurs while trying to create the
   *                         entry or retrieve its DN.
   */
  private static String addEntryNamedWithEntryUUID(
                             final LDAPConnection connection, final Entry entry)
          throws LDAPException
  {
    // Create the add request and add the entry to the server.
    final AddRequest addRequest = new AddRequest(entry);

    final boolean isCritical = true;
    addRequest.addControl(new NameWithEntryUUIDRequestControl(isCritical));

    System.out.println("Sending add request:");
    System.out.println(addRequest.toLDIFString());
    System.out.println();

    final LDAPResult addResult;
    try
    {
      addResult = connection.add(addRequest);
    }
    catch (final LDAPException e)
    {
      throw new LDAPException(e.getResultCode(),
           "Unable to add the provided entry with the name with entryUUID " +
                "request control:  " + StaticUtils.getExceptionMessage(e),
           e);
    }


    // Get the post-read response control from the add result and use that to
    // obtain the entry's actual DN.
    final PostReadResponseControl postReadResponseControl;
    try
    {
      postReadResponseControl = PostReadResponseControl.get(addResult);
    }
    catch (final LDAPException e)
    {
      throw new LDAPException(e.getResultCode(),
           "An error occurred while trying to get the post-read response " +
                "control from the add result:  " +
                StaticUtils.getExceptionMessage(e),
           e);
    }

    if (postReadResponseControl == null)
    {
      throw new LDAPException(ResultCode.CONTROL_NOT_FOUND,
           "The entry was successfully added, but the add response did not " +
                "include the expected post-read response control to " +
                "provide the entry's actual DN.");
    }

    return postReadResponseControl.getEntry().getDN();
  }



  /**
   * Displays an LDIF representation of the full entry that was added.
   *
   * @param  connection  The connection to use to communicate with the directory
   *                     server.
   * @param  dn          The DN of the entry to display.
   *
   * @throws  LDAPException  If a problem occurs while trying to create the
   *                         entry or retrieve its DN.
   */
  private static void displayFullEntry(final LDAPConnection connection,
                                       final String dn)
          throws LDAPException
  {
    // Retrieve the entry from the server.
    final Entry entry;
    try
    {
      final String[] requestedAttributes =
      {
        SearchRequest.ALL_USER_ATTRIBUTES,
        SearchRequest.ALL_OPERATIONAL_ATTRIBUTES
      };

      entry = connection.getEntry(dn, requestedAttributes);
    }
    catch (final LDAPException e)
    {
      throw new LDAPException(e.getResultCode(),
           "Unable to retrieve entry '" + dn + "' from the server:  " +
                StaticUtils.getExceptionMessage(e),
           e);
    }

    if (entry == null)
    {
      throw new LDAPException(ResultCode.NO_SUCH_OBJECT,
           "The request to retrieve entry '" + dn + "' succeeded but did " +
                "not return any entry.  This either means that the entry " +
                "does not exist, or that the client does not have permission " +
                "to access it.");
    }

    System.out.println("Full content of the resulting entry:");
    System.out.println(entry.toLDIFString());
  }
}
