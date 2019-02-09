/*
 * Copyright 2018 Neil A. Wilson
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2018 Neil A. Wilson
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
 * Copyright 2018 Neil A. Wilson
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
package com.dirmgr.example.crammd5;



import java.io.IOException;
import java.util.Collections;
import java.util.List;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.AuthorizeCallback;
import javax.security.sasl.Sasl;
import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServer;

import com.unboundid.ldap.listener.InMemoryRequestHandler;
import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.Filter;
import com.unboundid.ldap.sdk.ReadOnlyEntry;
import com.unboundid.ldap.sdk.SearchScope;
import com.unboundid.util.Debug;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.Validator;



/**
 * This class holds state information needed during CRAM-MD5 SASL processing.
 */
final class CRAMMD5BindState
      implements CallbackHandler
{
  // Indicates whether the password has been set.
  private boolean passwordSet;

  // The associated in-memory request handler.
  private final InMemoryRequestHandler requestHandler;

  // The entry for the target user.
  private ReadOnlyEntry userEntry;

  // The SASL server that will perform the core processing.
  private final SaslServer saslServer;

  // The authentication ID for the target user.
  private String authenticationID;



  /**
   * Creates a new CRAM-MD5 bind state object with the provided SASL server and
   * no property values.
   *
   * @param  requestHandler  The associated in-memory request handler.  It must
   *                         not be {@code null}.
   * @param  serverName      The fully-qualified name of the system on which the
   *                         server is running.  It must not be {@code null}.
   *
   * @throws  SaslException  If a problem is encountered while creating the
   *                         associated SASL server.
   */
  CRAMMD5BindState(final InMemoryRequestHandler requestHandler,
                   final String serverName)
       throws SaslException
  {
    Validator.ensureNotNullWithMessage(requestHandler,
         "CRAMMD5BindState.<init>.requestHandler must not be null");

    this.requestHandler = requestHandler;

    saslServer = Sasl.createSaslServer("CRAM-MD5", "ldap", serverName,
         Collections.<String,Object>emptyMap(), this);

    authenticationID = null;
    userEntry = null;
    passwordSet = false;
  }



  /**
   * Retrieves the SASL server that will perform the core processing.
   *
   * @return The SASL server that will perform the core processing.
   */
  SaslServer getSASLServer()
  {
    return saslServer;
  }



  /**
   * Retrieves the entry for the associated user, if available.
   *
   * @return  The entry for the associated user, or {@code null} if the user has
   *          not been identified.
   */
  ReadOnlyEntry getUserEntry()
  {
    return userEntry;
  }



  /**
   * Disposes of this cached state.
   */
  void dispose()
  {
    try
    {
      saslServer.dispose();
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
    }

    authenticationID = null;
    userEntry = null;
    passwordSet = false;
  }



  /**
   * Performs the necessary processing for the provided set of callbacks.
   *
   * @param callbacks The set of callbacks to be handled.
   *
   * @throws IOException If a problem is encountered that is not the result of
   * an unhandled callback.
   * @throws UnsupportedCallbackException If any of the provided callbacks is
   * unsupported.
   */
  @Override()
  public void handle(final Callback[] callbacks)
       throws IOException, UnsupportedCallbackException
  {
    for (final Callback c : callbacks)
    {
      if (c instanceof NameCallback)
      {
        final NameCallback nameCallback = (NameCallback) c;
        authenticationID = nameCallback.getDefaultName();

        if (authenticationID == null)
        {
          throw new IOException("No authentication ID provided");
        }

        resolveAuthenticationID();
      }
      else if (c instanceof PasswordCallback)
      {
        final PasswordCallback passwordCallback = (PasswordCallback) c;

        if (userEntry == null)
        {
          throw new IOException("Unable to determine the password until the " +
               "authentication ID has been provided.");
        }

        final String password = userEntry.getAttributeValue("userPassword");
        if (password == null)
        {
          throw new IOException("User '" + userEntry.getDN() +
               "' does not have a password.");
        }

        passwordCallback.setPassword(password.toCharArray());
        passwordSet = true;
      }
      else if (c instanceof AuthorizeCallback)
      {
        final AuthorizeCallback authorizeCallback = (AuthorizeCallback) c;

        if (userEntry == null)
        {
          throw new IOException("Unable to authorize the bind before the " +
               "authentication ID has been provided.");
        }

        if (!passwordSet)
        {
          throw new IOException("Unable to authorize the bind before the " +
               "password has been provided.");
        }

        authorizeCallback.setAuthorized(true);
        authorizeCallback.setAuthorizedID("dn:" + userEntry.getDN());
      }
      else
      {
        throw new UnsupportedCallbackException(c);
      }
    }
  }



  /**
   * Resolves the authentication ID to a user entry.
   *
   * @throws  IOException  If the authentication ID cannot be resolved to a
   *                       user entry.
   */
  private void resolveAuthenticationID()
          throws IOException
  {
    DN userDN = null;
    String userID = null;
    if (authenticationID.startsWith("dn:"))
    {
      try
      {
        userDN = new DN(authenticationID.substring(3));
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        throw new IOException(
             "Unable to extract the DN from authentication ID '" +
                  authenticationID + "':  " +
                  StaticUtils.getExceptionMessage(e),
             e);
      }
    }
    else if (authenticationID.startsWith("u:"))
    {
      userID = authenticationID.substring(2);
    }
    else
    {
      try
      {
        userDN = new DN(authenticationID);
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        userID = authenticationID;
      }
    }

    if (userDN == null)
    {
      final List<ReadOnlyEntry> matchingEntries;
      try
      {
        matchingEntries = requestHandler.search("", SearchScope.SUB,
             Filter.createEqualityFilter("uid", userID));
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        throw new IOException(
             "An error occurred while searching for the user with ID '" +
                  userID + "':  " + StaticUtils.getExceptionMessage(e),
             e);
      }

      if (matchingEntries.isEmpty())
      {
        throw new IOException("Unable to find any entries with user ID '" +
             userID + "'.");
      }

      if (matchingEntries.size() == 1)
      {
        userEntry = matchingEntries.get(0);
      }
      else
      {
        throw new IOException("Multiple entries have user ID '" + userID +
             "'.");
      }
    }
    else
    {
      userEntry = requestHandler.getEntry(userDN);
      if (userEntry == null)
      {
        throw new IOException("The server does not have an entry with DN " +
             userDN);
      }
    }
  }
}
