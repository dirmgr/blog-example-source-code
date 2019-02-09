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
package com.dirmgr.example.ldapjoin;



import javax.net.ssl.SSLSocketFactory;

import com.unboundid.ldap.sdk.DereferencePolicy;
import com.unboundid.ldap.sdk.Filter;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.SearchRequest;
import com.unboundid.ldap.sdk.SearchResult;
import com.unboundid.ldap.sdk.SearchResultEntry;
import com.unboundid.ldap.sdk.SearchScope;
import com.unboundid.ldap.sdk.unboundidds.controls.JoinBaseDN;
import com.unboundid.ldap.sdk.unboundidds.controls.JoinRequestControl;
import com.unboundid.ldap.sdk.unboundidds.controls.JoinRequestValue;
import com.unboundid.ldap.sdk.unboundidds.controls.JoinResultControl;
import com.unboundid.ldap.sdk.unboundidds.controls.JoinRule;
import com.unboundid.ldap.sdk.unboundidds.controls.JoinedEntry;
import com.unboundid.util.ColumnFormatter;
import com.unboundid.util.FormattableColumn;
import com.unboundid.util.HorizontalAlignment;
import com.unboundid.util.LDAPTestUtils;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ssl.AggregateTrustManager;
import com.unboundid.util.ssl.JVMDefaultTrustManager;
import com.unboundid.util.ssl.PromptTrustManager;
import com.unboundid.util.ssl.SSLUtil;



/**
 * This class provides a sample program that demonstrates the use of the LDAP
 * join control in the Ping Identity Directory Server and the UnboundID LDAP
 * SDK for Java.  It issues a search request to retrieve a user from the
 * directory, where that search where that search request includes a join
 * request control that uses a DN join to retrieve entry for that user's
 * manager, and a nested join that also uses a reverse DN join to retrieve the
 * entries for the manager's direct reports.
 */
public final class RetrieveUserManagerAndPeers
{
  /**
   * Runs this program with the provided set of arguments.
   *
   * @param  args  The command-line arguments provided to this program.  This
   *               program obtains all of the necessary information
   *               interactively and therefore does not require any command-line
   *               arguments.
   *
   * @throws  LDAPException  If a problem is encountered while communicating
   *                         with the Directory Server, or if it does not
   *                         contain the expected data.
   */
  public static void main(final String... args)
         throws LDAPException
  {
    // Establish a connection to the Directory Server.
    try (LDAPConnection connection = getConnection())
    {
      // Create a search request to retrieve a specified user from the server.
      final String searchBaseDN = "dc=example,dc=com";
      final String targetUserID = "ernest.employee";
      final String[] requestedAttributes =
      {
        "givenName",
        "sn",
        "mail",
        "telephoneNumber"
      };
      final SearchRequest searchRequest = new SearchRequest(searchBaseDN,
           SearchScope.SUB, Filter.createEqualityFilter("uid", targetUserID),
           requestedAttributes);

      // Create the join request control.  The outer join will use the DN join
      // rule to associate target the user with their boss via the manager
      // attribute in the user's entry.  The nested join will use the reverse DN
      // join to associate the manager with their direct reports, via the
      // manager attribute in the peer's entries.
      final JoinRequestValue nestedJoin = new JoinRequestValue(
           JoinRule.createReverseDNJoin("manager"),
           JoinBaseDN.createUseSearchBaseDN(),
           SearchScope.SUB,
           DereferencePolicy.NEVER,
           null, // No size limit.
           Filter.createNOTFilter(// Don't include employee in nested results
                Filter.createEqualityFilter("uid", targetUserID)),
           requestedAttributes,
           false, // Include outer join entry even if not joined with anything.
           null); // No nested join.
      final JoinRequestValue outerJoin = new JoinRequestValue(
           JoinRule.createDNJoin("manager"),
           JoinBaseDN.createUseSearchBaseDN(),
           SearchScope.SUB,
           DereferencePolicy.NEVER,
           null, // No size limit.
           null, // No additional filter
           requestedAttributes,
           false, // Include outer join entry even if not joined with anything.
           nestedJoin); // No nested join.
      final JoinRequestControl joinRequestControl =
           new JoinRequestControl(outerJoin);
      searchRequest.addControl(joinRequestControl);

      // Send the search to the server and get the results back.  Make sure that
      // the search succeeded and returned exactly one entry.
      final SearchResult searchResult = connection.search(searchRequest);
      LDAPTestUtils.assertResultCodeEquals(searchResult, ResultCode.SUCCESS);
      LDAPTestUtils.assertEntriesReturnedEquals(searchResult, 1);

      // Create a column formatter that will be used to display the
      // results.
      final ColumnFormatter columnFormatter = new ColumnFormatter(
           new FormattableColumn(9, HorizontalAlignment.LEFT, "User Type"),
           new FormattableColumn(10, HorizontalAlignment.LEFT, "First Name"),
           new FormattableColumn(10, HorizontalAlignment.LEFT, "Last Name"),
           new FormattableColumn(32, HorizontalAlignment.LEFT, "Email Address"),
           new FormattableColumn(15, HorizontalAlignment.LEFT, "Phone Number"));
      for (final String headerLine : columnFormatter.getHeaderLines(true))
      {
        System.out.println(headerLine);
      }

      // Get the search result entry and add it to the table.
      final SearchResultEntry employeeEntry =
           searchResult.getSearchEntries().get(0);
      System.out.println(columnFormatter.formatRow(
           "Employee",
           employeeEntry.getAttributeValue("givenName"),
           employeeEntry.getAttributeValue("sn"),
           employeeEntry.getAttributeValue("mail"),
           employeeEntry.getAttributeValue("telephoneNumber")));

      // Extract the join result control from the search result entry.
      LDAPTestUtils.assertHasControl(employeeEntry,
           JoinResultControl.JOIN_RESULT_OID);
      JoinResultControl joinResultControl =
           JoinResultControl.get(employeeEntry);

      // Iterate through the joined entries and print the results.
      for (final JoinedEntry bossEntry : joinResultControl.getJoinResults())
      {
        System.out.println(columnFormatter.formatRow(
             "Boss",
             bossEntry.getAttributeValue("givenName"),
             bossEntry.getAttributeValue("sn"),
             bossEntry.getAttributeValue("mail"),
             bossEntry.getAttributeValue("telephoneNumber")));

        for (final JoinedEntry peerEntry :
             bossEntry.getNestedJoinResults())
        {
          System.out.println(columnFormatter.formatRow(
               "Peer",
               peerEntry.getAttributeValue("givenName"),
               peerEntry.getAttributeValue("sn"),
               peerEntry.getAttributeValue("mail"),
               peerEntry.getAttributeValue("telephoneNumber")));
        }
      }
    }
  }



  /**
   * Establishes a connection to the directory server and authenticates it as a
   * specified user.
   *
   * @return  The connection that was established.
   *
   * @throws  LDAPException  If a problem is encountered while establishing or
   *                         authenticating the connection.
   */
  private static LDAPConnection getConnection()
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

    // Authenticate to the server.  If the authentication fails, then make sure
    // the connection gets closed before propagating the exception to the
    // caller.
    boolean authenticationSucceeded = false;
    try
    {
      final String bindDN =
           "cn=LDAP Join Example,ou=Applications,dc=example,dc=com";
      final String bindPassword = "joinUserPassword";
      connection.bind(bindDN, bindPassword);
      authenticationSucceeded = true;
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
}
