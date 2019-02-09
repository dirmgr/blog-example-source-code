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



import java.util.List;
import java.util.WeakHashMap;
import javax.security.sasl.SaslServer;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.listener.InMemoryRequestHandler;
import com.unboundid.ldap.listener.InMemorySASLBindHandler;
import com.unboundid.ldap.listener.LDAPListenerClientConnection;
import com.unboundid.ldap.sdk.BindResult;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.ReadOnlyEntry;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;



/**
 * This class defines a SASL bind handler that may be used to provide support
 * for the CRAM-MD5 mechanism.  Note that this implementation is primarily for
 * demonstration purposes, as CRAM-MD5 is an old and insecure mechanism that is
 * no longer recommended for use.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class CRAMMD5BindHandler
       extends InMemorySASLBindHandler
{
  // The fully-qualified name of the sever system.
  private final String serverName;

  // A map of the cached state information used during processing.
  private final WeakHashMap<LDAPListenerClientConnection,CRAMMD5BindState>
       cachedState;



  /**
   * Creates a new instance of this SASL bind handler.
   *
   * @param  serverName  The fully-qualified name of the system on which the
   *                     server is running.  It must not be {@code null}.
   */
  public CRAMMD5BindHandler(final String serverName)
  {
    Validator.ensureNotNullWithMessage(serverName,
         "CRAMMD5BindHandler.<init>.serverName must not be null");

    this.serverName = serverName;
    cachedState = new WeakHashMap<>(10);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public String getSASLMechanismName()
  {
    return "CRAM-MD5";
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public BindResult processSASLBind(final InMemoryRequestHandler handler,
                                    final int messageID, final DN bindDN,
                                    final ASN1OctetString credentials,
                                    final List<Control> controls)
  {
    // Get the request credentials bytes.
    final byte[] requestCredentialsBytes;
    if (credentials == null)
    {
      requestCredentialsBytes = StaticUtils.NO_BYTES;
    }
    else
    {
      requestCredentialsBytes = credentials.getValue();
    }


    // See if we already have cached state for the provided client connection.
    CRAMMD5BindState state = cachedState.get(handler.getClientConnection());
    if (state == null)
    {
      // We will only allow a null state if the provided set of credentials is
      // empty, indicating that the client has just started the authentication
      // process.
      if (requestCredentialsBytes.length > 0)
      {
        return new BindResult(messageID, ResultCode.INVALID_CREDENTIALS,
             "CRAM-MD5 bind request with credentials provided on a " +
                  "connection for which no SASL server was available.",
             null, null, null);
      }
    }
    else if (requestCredentialsBytes.length == 0)
    {
      // We have existing SASL state for the connection, but the client is
      // starting a new bind flow.  Get rid of the old state.
      state.dispose();
      state = null;
    }


    // If the SASL state is null, then create a new one.
    if (state == null)
    {
      try
      {
        state = new CRAMMD5BindState(handler, serverName);
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        return new BindResult(messageID, ResultCode.OTHER,
             "Unable to create a SASL server for handling the CRAM-MD5 bind " +
                  "request:  " + StaticUtils.getExceptionMessage(e),
             null, null, null);
      }

      cachedState.put(handler.getClientConnection(), state);
    }


    // Process the provided set of request credentials.
    final byte[] serverSASLCredentialsBytes;
    final SaslServer saslServer = state.getSASLServer();
    try
    {
      serverSASLCredentialsBytes =
           saslServer.evaluateResponse(requestCredentialsBytes);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);

      try
      {
        state.dispose();
      }
      catch (final Exception e2)
      {
        Debug.debugException(e2);
      }

      return new BindResult(messageID, ResultCode.INVALID_CREDENTIALS,
           "Unable to process the provided SASL credentials:  " +
                StaticUtils.getExceptionMessage(e),
           null, null, null);
    }

    final ASN1OctetString serverSASLCredentials;
    if (serverSASLCredentialsBytes == null)
    {
      serverSASLCredentials = null;
    }
    else
    {
      serverSASLCredentials = new ASN1OctetString((byte) 0x87,
           serverSASLCredentialsBytes);
    }



    // If the SASL server indicates that processing isn't yet complete, then
    // return a "SASL bind in progress" result with the generated credentials,
    // and we're done for this round.
    if (! saslServer.isComplete())
    {
      return new BindResult(messageID, ResultCode.SASL_BIND_IN_PROGRESS, null,
           null, null, null, serverSASLCredentials);
    }


    // The SASL bind is complete.  It may or may not have been successful, but
    // we'll want to make sure to get rid of the SASL server either way, so do
    // that in a finally block.
    try
    {
      final String authorizationID = saslServer.getAuthorizationID();
      if (authorizationID == null)
      {
        return new BindResult(messageID, ResultCode.INVALID_CREDENTIALS,
             "The SASL CRAM-MD5 bind failed", null, null, null,
             serverSASLCredentials);
      }

      final ReadOnlyEntry userEntry = state.getUserEntry();
      if (userEntry == null)
      {
        return new BindResult(messageID, ResultCode.INVALID_CREDENTIALS,
             "The SASL CRAM-MD5 bind failed", null, null, null,
             serverSASLCredentials);
      }

      try
      {
        handler.setAuthenticatedDN(userEntry.getParsedDN());
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        return new BindResult(messageID, ResultCode.INVALID_CREDENTIALS,
             "Unable to parse the resulting bind DN " + userEntry.getDN(), null,
             null, null, serverSASLCredentials);
      }

      return new BindResult(messageID, ResultCode.SUCCESS,
           "The SASL CRAM-MD5 bind succeeded", null, null, null,
           serverSASLCredentials);
    }
    finally
    {
      cachedState.remove(handler.getClientConnection());

      try
      {
        state.dispose();
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
      }
    }
  }
}
