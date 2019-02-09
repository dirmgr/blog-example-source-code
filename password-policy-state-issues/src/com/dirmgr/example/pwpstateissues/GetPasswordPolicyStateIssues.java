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
package com.dirmgr.example.pwpstateissues;



import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.List;

import com.unboundid.ldap.sdk.BindResult;
import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.RootDSE;
import com.unboundid.ldap.sdk.SimpleBindRequest;
import com.unboundid.ldap.sdk.unboundidds.controls.AuthenticationFailureReason;
import com.unboundid.ldap.sdk.unboundidds.controls.
            GetPasswordPolicyStateIssuesRequestControl;
import com.unboundid.ldap.sdk.unboundidds.controls.
            GetPasswordPolicyStateIssuesResponseControl;
import com.unboundid.ldap.sdk.unboundidds.controls.RetainIdentityRequestControl;
import com.unboundid.ldap.sdk.unboundidds.extensions.
            PasswordPolicyStateAccountUsabilityError;
import com.unboundid.ldap.sdk.unboundidds.extensions.
            PasswordPolicyStateAccountUsabilityNotice;
import com.unboundid.ldap.sdk.unboundidds.extensions.
            PasswordPolicyStateAccountUsabilityWarning;
import com.unboundid.util.PasswordReader;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ssl.AggregateTrustManager;
import com.unboundid.util.ssl.JVMDefaultTrustManager;
import com.unboundid.util.ssl.PromptTrustManager;
import com.unboundid.util.ssl.SSLUtil;



/**
 * This class provides an interactive command-line tool demonstrates the use of
 * the get password policy state issues control in the Ping Identity Directory
 * Server and the UnboundID LDAP SDK for Java. It first binds as an application
 * account with the permit-get-password-policy-state-issues privilege and the
 * ability to use both the get password policy state issues and the retain
 * identity controls, and will then use those controls while attempting to
 * authenticate a specified user. If the authentication fails, then the reason
 * for that failure will be displayed to the user. In any case, any password
 * policy state errors, warnings, and notices included in the get password
 * policy state issues response control will be displayed.
 */
public class GetPasswordPolicyStateIssues
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
    final BufferedReader in =
         new BufferedReader(new InputStreamReader(System.in));

    try (LDAPConnection connection = getLDAPConnection(in))
    {
      System.out.println();
      checkRootDSE(connection);

      System.out.println();
      bindAsApplicationAccount(connection, in);

      System.out.println();
      bindWithGetPasswordPolicyStateIssues(connection, in);
    }
  }



  /**
   * Establishes a connection to an LDAP directory server.
   *
   * @param  in  The buffered reader to use to read from standard input.
   *
   * @return  The connection that was established.
   */
  private static LDAPConnection getLDAPConnection(final BufferedReader in)
  {
    while (true)
    {
      final String address = readLine(
           "Enter the directory server address: ", in);
      final int port = readInteger("Enter the directory server port: ", 1,
           65535, in);

      final boolean secure = readBoolean(
           "Do you want the connection to be secured with TLS? ", in);

      if (secure)
      {
        try
        {
          final SSLUtil sslUtil = new SSLUtil(new AggregateTrustManager(false,
               JVMDefaultTrustManager.getInstance(), new PromptTrustManager()));
          return new LDAPConnection(sslUtil.createSSLSocketFactory(), address,
               port);
        }
        catch (final Exception e)
        {
          System.err.println("ERROR: Unable to establish a secure " +
               "connection to " + address + ':' + port + ": " +
               StaticUtils.getExceptionMessage(e));
          System.err.println();
        }
      }
      else
      {
        try
        {
          return new LDAPConnection(address, port);
        }
        catch (final Exception e)
        {
          System.err.println(
               "ERROR: Unable to establish an LDAP connection to " +
                    address + ':' + port + ": " +
                    StaticUtils.getExceptionMessage(e));
          System.err.println();
        }
      }
    }
  }



  /**
   * Checks the directory server root DSE to ensure that it claims to support
   * the get password quality requirements extended operation, the password
   * modify extended operation, and the password validation details request
   * control.  If we can retrieve the root DSE but can't verify support, then
   * display a warning message.  If we cannot retrieve the root DSE, then don't
   * complain because the server may prohibit anonymous requests, even when
   * targeting the root DSE.
   *
   * @param  connection  The connection to use to communicate with the directory
   *                     server.
   */
  private static void checkRootDSE(final LDAPConnection connection)
  {
    final RootDSE rootDSE;
    try
    {
      rootDSE = connection.getRootDSE();
      if (rootDSE == null)
      {
        // This is fine.  The root DSE might not be accessible over an
        // unauthenticated connection.
        return;
      }
    }
    catch (final Exception e)
    {
      // This is fine.  The root DSE might not be accessible over an
      // unauthenticated connection.
      return;
    }


    boolean warned = false;
    if (! rootDSE.supportsControl(
         GetPasswordPolicyStateIssuesRequestControl.
              GET_PASSWORD_POLICY_STATE_ISSUES_REQUEST_OID))
    {
      warned = true;
      System.err.println();
      System.err.println("WARNING: The directory server root DSE does not " +
           "claim support for the get password policy state issues request " +
           "control.  This tool requires support for that control.");
    }

    if (! rootDSE.supportsControl(
         RetainIdentityRequestControl.RETAIN_IDENTITY_REQUEST_OID))
    {
      warned = true;
      System.err.println();
      System.err.println("WARNING: The directory server root DSE does not " +
           "claim support for the retain identity request control.  This " +
           "tool requires support for that control.");
    }

    if (! warned)
    {
      System.out.println("The directory server appears to support both the " +
           "get password policy state issues request control and the retain " +
           "identity request control.");
    }
  }



  /**
   * Performs a bind operation to authenticate as an application account with
   * the ability to use the get password policy state issues and retain identity
   * request controls.
   *
   * @param  connection  The connection to use to communicate with the directory
   *                     server.
   * @param  in          The buffered reader to use to read from standard input.
   *
   * @return  {@code true} if the authentication attempt was successful, or
   *          {@code false} if not.
   */
  private static void bindAsApplicationAccount(final LDAPConnection connection,
                                               final BufferedReader in)
  {
    while (true)
    {
      final DN bindDN = readDN(
           "Enter the DN of an account that has permission to use the get " +
                "password policy state issues and retain identity request " +
                "controls: ", in);

      final String password = readPassword(
           "Enter the password for '" + bindDN + "': ");

      try
      {
        connection.bind(bindDN.toString(), password);
        System.out.println("Successfully authenticated as " + bindDN);
        return;
      }
      catch (final Exception e)
      {
        System.err.println("ERROR: Unable to bind as user '" + bindDN +
             "' with the provided password: " +
             StaticUtils.getExceptionMessage(e));
        System.err.println();
      }
    }
  }



  /**
   * Performs a bind operation that contains both the get password policy state
   * issues and retain identity request controls.  The contents of the response
   * control will be displayed to the user.
   *
   * @param  connection  The connection to use to communicate with the directory
   *                     server.
   * @param  in          The buffered reader to use to read from standard input.
   */
  private static void bindWithGetPasswordPolicyStateIssues(
                           final LDAPConnection connection,
                           final BufferedReader in)
  {
    final DN bindDN = readDN(
         "Enter the DN of the user to attempt to authenticate while using " +
              "the get password policy state issues request control: ",
         in);

    final String password =
         readPassword("Enter the password for '" + bindDN + ": ");

    final SimpleBindRequest bindRequest = new SimpleBindRequest(bindDN,
         password, new GetPasswordPolicyStateIssuesRequestControl(),
         new RetainIdentityRequestControl());

    BindResult bindResult;
    try
    {
      bindResult = connection.bind(bindRequest);
      System.out.println("Successfully authenticated as " + bindDN);
    }
    catch (final LDAPException e)
    {
      bindResult = new BindResult(e);
      System.err.println("The attempt to bind as '" + bindDN + "' failed:");
      System.out.println("LDAP Result Code: " + e.getResultCode());
      if (e.getDiagnosticMessage() != null)
      {
        System.out.println("Diagnostic Message: " + e.getDiagnosticMessage());
      }
    }

    final GetPasswordPolicyStateIssuesResponseControl pwpStateIssuesResponse;
    try
    {
      pwpStateIssuesResponse =
           GetPasswordPolicyStateIssuesResponseControl.get(bindResult);
    }
    catch (final Exception e)
    {
      System.err.println("ERROR: Unable to decode the get password policy " +
           "state issues response control from the bind result: " +
           StaticUtils.getExceptionMessage(e));
      return;
    }

    if (pwpStateIssuesResponse == null)
    {
      System.err.println("ERROR: The bind response did not include a get " +
           "password policy state issues response control.  No additional " +
           "information is available about the user's password policy state.");
      return;
    }

    final AuthenticationFailureReason authFailureReason =
         pwpStateIssuesResponse.getAuthenticationFailureReason();
    if (authFailureReason == null)
    {
      System.out.println();
      System.out.println("There is no authentication failure reason.");
    }
    else
    {
      System.out.println();
      System.out.println("Authentication Failure Reason Name: " +
           authFailureReason.getName());
      System.out.println("Authentication Failure Reason Type: " +
           authFailureReason.getIntValue());
      System.out.println("Authentication Failure Reason Message: " +
           authFailureReason.getMessage());
    }

    final List<PasswordPolicyStateAccountUsabilityError> pwpStateErrors =
         pwpStateIssuesResponse.getErrors();
    if (pwpStateErrors.isEmpty())
    {
      System.out.println();
      System.out.println("There are no password policy state errors.");
    }
    else
    {
      for (final PasswordPolicyStateAccountUsabilityError error :
           pwpStateErrors)
      {
        System.out.println();
        System.out.println("Usability Error Name: " + error.getName());
        System.out.println("Usability Error Type: " + error.getIntValue());
        System.out.println("Usability Error Message: " + error.getMessage());
      }
    }

    final List<PasswordPolicyStateAccountUsabilityWarning> pwpStateWarnings =
         pwpStateIssuesResponse.getWarnings();
    if (pwpStateWarnings.isEmpty())
    {
      System.out.println();
      System.out.println("There are no password policy state warnings.");
    }
    else
    {
      for (final PasswordPolicyStateAccountUsabilityWarning warning :
           pwpStateWarnings)
      {
        System.out.println();
        System.out.println("Usability Warning Name: " + warning.getName());
        System.out.println("Usability Warning Type: " + warning.getIntValue());
        System.out.println("Usability Warning Message: " +
             warning.getMessage());
      }
    }

    final List<PasswordPolicyStateAccountUsabilityNotice> pwpStateNotices =
         pwpStateIssuesResponse.getNotices();
    if (pwpStateNotices.isEmpty())
    {
      System.out.println();
      System.out.println("There are no password policy state notices.");
    }
    else
    {
      for (final PasswordPolicyStateAccountUsabilityNotice notice :
           pwpStateNotices)
      {
        System.out.println();
        System.out.println("Usability Notice Name: " + notice.getName());
        System.out.println("Usability Notice Type: " + notice.getIntValue());
        System.out.println("Usability Notice Message: " + notice.getMessage());
      }
    }
  }



  /**
   * Reads a non-empty line from standard input.
   *
   * @param  prompt  The prompt to display before reading the input.
   * @param  in      The buffered reader to use to read from standard input.
   *
   * @return  The line read from standard input.
   */
  private static String readLine(final String prompt, final BufferedReader in)
  {
    while (true)
    {
      System.out.print(prompt);

      final String line;
      try
      {
        line = in.readLine();
      }
      catch (final Exception e)
      {
        throw new RuntimeException(
             "ERROR: Unable to read from the terminal: " +
                  StaticUtils.getExceptionMessage(e),
             e);
      }

      if (line == null)
      {
        throw new RuntimeException(
             "ERROR: Unable to read from the terminal because standard input " +
                  "has been closed.");
      }

      if (line.isEmpty())
      {
        System.err.println("ERROR: The value must not be empty.");
        System.err.println();
      }
      else
      {
        return line;
      }
    }
  }



  /**
   * Reads an integer from standard input.
   *
   * @param  prompt  The prompt to display before reading the input.
   * @praam  min     The minimum allowed value.
   * @praam  max     The maximum allowed value.
   * @param  in      The buffered reader to use to read from standard input.
   *
   * @return  The integer value that was read.
   */
  private static int readInteger(final String prompt, final int min,
                                 final int max, final BufferedReader in)
  {
    while (true)
    {
      final String line = readLine(prompt, in).trim();

      final int intValue;
      try
      {
        intValue = Integer.parseInt(line);
      }
      catch (final Exception e)
      {
        System.err.println("ERROR: The value must be an integer.");
        System.err.println();
        continue;
      }

      if (intValue < min)
      {
        System.err.println(
             "ERROR: The value must be greater than or equal to " + min + '.');
        System.err.println();
        continue;
      }

      if (intValue > max)
      {
        System.err.println(
             "ERROR: The value must be less than or equal to " + max + '.');
        System.err.println();
        continue;
      }

      return intValue;
    }
  }



  /**
   * Reads a boolean value from standard input.
   *
   * @param  prompt  The prompt to display before reading the input.
   * @param  in      The buffered reader to use to read from standard input.
   *
   * @return  The boolean value that was read.
   */
  private static boolean readBoolean(final String prompt,
                                     final BufferedReader in)
  {
    while (true)
    {
      final String line  = readLine(prompt, in).trim();

      if (line.equalsIgnoreCase("yes") || line.equalsIgnoreCase("y"))
      {
        return true;
      }
      else if (line.equalsIgnoreCase("no") || line.equalsIgnoreCase("n"))
      {
        return false;
      }
      else
      {
        System.err.println(
             "ERROR: The value must be either 'yes' or 'no'.");
        System.err.println();
      }
    }
  }



  /**
   * Reads a DN from standard input.
   *
   * @param  prompt  The prompt to display before reading the input.
   * @param  in      The buffered reader to use to read from standard input.
   *
   * @return  The DN that was read.
   */
  private static DN readDN(final String prompt, final BufferedReader in)
  {
    while (true)
    {
      final String line = readLine(prompt, in).trim();

      try
      {
        return new DN(line);
      }
      catch (final Exception e)
      {
        System.err.println(
             "ERROR: Unable to parse the value as a DN: " +
                  StaticUtils.getExceptionMessage(e));
        System.err.println();
      }
    }
  }



  /**
   * Reads a password from standard input.
   *
   * @param  prompt  The prompt to display before reading the input.
   *
   * @return  The DN that was read.
   */
  private static String readPassword(final String prompt)
  {
    while (true)
    {
      System.out.print(prompt);

      final char[] passwordChars;
      try
      {
        passwordChars = PasswordReader.readPasswordChars();
      }
      catch (final Exception e)
      {
        throw new RuntimeException(
             "ERROR: Unable to read the password: " +
                  StaticUtils.getExceptionMessage(e),
             e);
      }

      if (passwordChars.length == 0)
      {
        System.err.println("ERROR: The password must not be empty.");
        System.err.println();
        continue;
      }

      return new String(passwordChars);
    }
  }
}
