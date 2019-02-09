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



import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.ldap.sdk.BindResult;
import com.unboundid.ldap.sdk.CRAMMD5BindRequest;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.LDAPTestUtils;



/**
 * This class demonstrates how to use the {@link CRAMMD5BindHandler} and
 * performs some basic testing of it.
 */
public class TestCRAMMD5BindHandler
{
  /**
   * Creates an in-memory directory server instance with the CRAM-MD5 bind
   * handler and runs some tests against it.
   *
   * @param  args  The provided command-line arguments.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  public static void main(final String... args)
         throws Exception
  {
    final InMemoryDirectoryServerConfig config =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");
    config.addSASLBindHandler(new CRAMMD5BindHandler("localhost"));

    final InMemoryDirectoryServer ds = new InMemoryDirectoryServer(config);
    ds.startListening();

    try (final LDAPConnection conn = ds.getConnection())
    {
      conn.add(
           "dn: dc=example,dc=com",
           "objectClass: top",
           "objectClass: domain",
           "dc: example");
      conn.add(
           "dn: uid=test.user,dc=example,dc=com",
           "objectClass: top",
           "objectClass: person",
           "objectClass: organizationalPerson",
           "objectClass: inetOrgPerson",
           "uid: test.user",
           "givenName: Test",
           "sn: User",
           "cn: Test User",
           "userPassword: password");

      BindResult bindResult;
      try
      {
        bindResult = conn.bind(new CRAMMD5BindRequest(
             "dn:uid=test.user,dc=example,dc=com", "password"));
      }
      catch (final LDAPException e)
      {
        bindResult = new BindResult(e);
      }

      System.out.println("Expected success (dn:) bind result was " +
           bindResult);
      LDAPTestUtils.assertResultCodeEquals(bindResult, ResultCode.SUCCESS);


      try
      {
        bindResult = conn.bind(new CRAMMD5BindRequest(
             "u:test.user", "password"));
      }
      catch (final LDAPException e)
      {
        bindResult = new BindResult(e);
      }

      System.out.println("Expected success (u:) bind result was " +
           bindResult);
      LDAPTestUtils.assertResultCodeEquals(bindResult, ResultCode.SUCCESS);


      try
      {
        bindResult = conn.bind(new CRAMMD5BindRequest(
             "uid=test.user,dc=example,dc=com", "password"));
      }
      catch (final LDAPException e)
      {
        bindResult = new BindResult(e);
      }

      System.out.println("Expected success (implicit DN) bind result was " +
           bindResult);
      LDAPTestUtils.assertResultCodeEquals(bindResult, ResultCode.SUCCESS);


      try
      {
        bindResult = conn.bind(new CRAMMD5BindRequest(
             "test.user", "password"));
      }
      catch (final LDAPException e)
      {
        bindResult = new BindResult(e);
      }

      System.out.println("Expected success (implicit uid) bind result was " +
           bindResult);
      LDAPTestUtils.assertResultCodeEquals(bindResult, ResultCode.SUCCESS);


      try
      {
        bindResult = conn.bind(new CRAMMD5BindRequest(
             "dn:uid=missing,dc=example,dc=com", "password"));
      }
      catch (final LDAPException e)
      {
        bindResult = new BindResult(e);
      }

      System.out.println("Expected failure (no such DN) bind result was " +
           bindResult);
      LDAPTestUtils.assertResultCodeEquals(bindResult,
           ResultCode.INVALID_CREDENTIALS);


      try
      {
        bindResult = conn.bind(new CRAMMD5BindRequest(
             "u:missing", "password"));
      }
      catch (final LDAPException e)
      {
        bindResult = new BindResult(e);
      }

      System.out.println("Expected failure (no such uid) bind result was " +
           bindResult);
      LDAPTestUtils.assertResultCodeEquals(bindResult,
           ResultCode.INVALID_CREDENTIALS);


      try
      {
        bindResult = conn.bind(new CRAMMD5BindRequest(
             "dn:malformed", "password"));
      }
      catch (final LDAPException e)
      {
        bindResult = new BindResult(e);
      }

      System.out.println("Expected failure (malformed DN) bind result was " +
           bindResult);
      LDAPTestUtils.assertResultCodeEquals(bindResult,
           ResultCode.INVALID_CREDENTIALS);


      try
      {
        bindResult = conn.bind(new CRAMMD5BindRequest(
             "dn:uid=test.user,dc=example,dc=com", "wrong"));
      }
      catch (final LDAPException e)
      {
        bindResult = new BindResult(e);
      }

      System.out.println("Expected failure (wrong password) bind result was " +
           bindResult);
      LDAPTestUtils.assertResultCodeEquals(bindResult,
           ResultCode.INVALID_CREDENTIALS);

      System.out.println("All tests yielded the expected results.");
    }
    finally
    {
      ds.shutDown(true);
    }
  }
}
