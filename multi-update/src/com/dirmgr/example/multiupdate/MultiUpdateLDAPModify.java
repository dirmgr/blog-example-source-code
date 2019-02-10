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
package com.dirmgr.example.multiupdate;



import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;

import com.unboundid.ldap.sdk.AddRequest;
import com.unboundid.ldap.sdk.DeleteRequest;
import com.unboundid.ldap.sdk.ExtendedResult;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPRequest;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.ModifyDNRequest;
import com.unboundid.ldap.sdk.ModifyRequest;
import com.unboundid.ldap.sdk.OperationType;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.unboundidds.extensions.MultiUpdateErrorBehavior;
import com.unboundid.ldap.sdk.unboundidds.extensions.MultiUpdateExtendedRequest;
import com.unboundid.ldap.sdk.unboundidds.extensions.MultiUpdateExtendedResult;
import com.unboundid.ldif.LDIFAddChangeRecord;
import com.unboundid.ldif.LDIFChangeRecord;
import com.unboundid.ldif.LDIFDeleteChangeRecord;
import com.unboundid.ldif.LDIFModifyChangeRecord;
import com.unboundid.ldif.LDIFModifyDNChangeRecord;
import com.unboundid.ldif.LDIFReader;
import com.unboundid.util.LDAPCommandLineTool;
import com.unboundid.util.ObjectPair;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.args.ArgumentException;
import com.unboundid.util.args.ArgumentParser;
import com.unboundid.util.args.FileArgument;
import com.unboundid.util.args.StringArgument;



/**
 * This class provides an LDAP command-line tool that demonstrates the use of
 * the multi-update extended operation in the Ping Identity Directory Server and
 * the UnboundID LDAP SDK for Java.  It provides a simplified version of the
 * ldapmodify tool that only reads the changes to apply from an LDIF file and
 * sends them all to the server in a single multi-update operation.
 */
public final class MultiUpdateLDAPModify
       extends LDAPCommandLineTool
{
  /**
   * The value that should be used for the error behavior argument if the
   * processing should abort after the first error.
   */
  private static final String ERROR_BEHAVIOR_ABORT_ON_ERROR = "abort-on-error";



  /**
   * The value that should be used for the error behavior argument if the
   * changes should be processed atomically.
   */
  private static final String ERROR_BEHAVIOR_ATOMIC = "atomic";



  /**
   * The value that should be used for the error behavior argument if the
   * processing should continue even after an error occurs.
   */
  private static final String ERROR_BEHAVIOR_CONTINUE_ON_ERROR =
       "continue-on-error";



  // The argument used to specify the path to the LDIF file containing the
  // changes to process.
  private FileArgument ldifFileArgument;

  // The argument that specifies the behavior to exhibit if an error occurs
  // during processing.
  private StringArgument errorBehaviorArgument;



  /**
   * Invokes this tool with the provided set of command-line arguments.
   *
   * @param  args  The command-line arguments provided to this program.
   */
  public static void main(final String... args)
  {
    final ResultCode resultCode = main(System.out, System.err, args);
    if (resultCode != ResultCode.SUCCESS)
    {
      System.exit(resultCode.intValue());
    }
  }



  /**
   * Invokes this tool with the provided set of command-line arguments.
   *
   * @param  out   The output stream to use for standard output.  It may be
   *               {@code null} if standard output should be suppressed.
   * @param  err   The output stream to use for standard error.  It may be
   *               {@code null} if standard error should be suppressed.
   * @param  args  The command-line arguments provided to this program.
   */
  public static ResultCode main(final OutputStream out, final OutputStream err,
                                final String... args)
  {
    final MultiUpdateLDAPModify tool = new MultiUpdateLDAPModify(out, err);
    return tool.runTool(args);
  }



  /**
   * Creates an instance of this tool with the provided output and error
   * streams.
   *
   * @param  out  The output stream to use for standard output.  It may be
   *              {@code null} if standard output should be suppressed.
   * @param  err  The output stream to use for standard error.  It may be
   *              {@code null} if standard error should be suppressed.
   */
  public MultiUpdateLDAPModify(final OutputStream out, final OutputStream err)
  {
    super(out, err);
  }



  /**
   * Retrieves the name of this tool.  It should be the name of the command used
   * to invoke this tool.
   *
   * @return  The name for this tool.
   */
  @Override()
  public String getToolName()
  {
    return "multi-update-ldapmodify";
  }



  /**
   * Retrieves a human-readable description for this tool.  If the description
   * should include multiple paragraphs, then this method should return the text
   * for the first paragraph, and the
   * {@link #getAdditionalDescriptionParagraphs()} method should be used to
   * return the text for the subsequent paragraphs.
   *
   * @return  A human-readable description for this tool.
   */
  @Override()
  public String getToolDescription()
  {
    return "Reads a set of changes from an LDIF file and sends them to a " +
         "Ping Identity Directory Server for processing in a multi-update " +
         "extended request.";
  }



  /**
   * Retrieves a version string for this tool, if available.
   *
   * @return  A version string for this tool, or {@code null} if none is
   *          available.
   */
  @Override()
  public String getToolVersion()
  {
    return "1.0.0";
  }



  /**
   * Indicates whether this tool should provide support for an interactive mode,
   * in which the tool offers a mode in which the arguments can be provided in
   * a text-driven menu rather than requiring them to be given on the command
   * line.  If interactive mode is supported, it may be invoked using the
   * "--interactive" argument.  Alternately, if interactive mode is supported
   * and {@link #defaultsToInteractiveMode()} returns {@code true}, then
   * interactive mode may be invoked by simply launching the tool without any
   * arguments.
   *
   * @return  {@code true} if this tool supports interactive mode, or
   *          {@code false} if not.
   */
  @Override()
  public boolean supportsInteractiveMode()
  {
    return true;
  }



  /**
   * Indicates whether this tool defaults to launching in interactive mode if
   * the tool is invoked without any command-line arguments.  This will only be
   * used if {@link #supportsInteractiveMode()} returns {@code true}.
   *
   * @return  {@code true} if this tool defaults to using interactive mode if
   *          launched without any command-line arguments, or {@code false} if
   *          not.
   */
  @Override()
  public boolean defaultsToInteractiveMode()
  {
    return true;
  }



  /**
   * Indicates whether this tool supports the use of a properties file for
   * specifying default values for arguments that aren't specified on the
   * command line.
   *
   * @return  {@code true} if this tool supports the use of a properties file
   *          for specifying default values for arguments that aren't specified
   *          on the command line, or {@code false} if not.
   */
  @Override()
  public boolean supportsPropertiesFile()
  {
    return true;
  }



  /**
   * Indicates whether this tool should provide arguments for redirecting output
   * to a file.  If this method returns {@code true}, then the tool will offer
   * an "--outputFile" argument that will specify the path to a file to which
   * all standard output and standard error content will be written, and it will
   * also offer a "--teeToStandardOut" argument that can only be used if the
   * "--outputFile" argument is present and will cause all output to be written
   * to both the specified output file and to standard output.
   *
   * @return  {@code true} if this tool should provide arguments for redirecting
   *          output to a file, or {@code false} if not.
   */
  @Override()
  protected boolean supportsOutputFile()
  {
    return true;
  }



  /**
   * Adds the arguments needed by this command-line tool to the provided
   * argument parser which are not related to connecting or authenticating to
   * the directory server.
   *
   * @param  parser  The argument parser to which the arguments should be added.
   *
   * @throws  ArgumentException  If a problem occurs while adding the arguments.
   */
  @Override()
  public void addNonLDAPArguments(ArgumentParser parser)
         throws ArgumentException
  {
    ldifFileArgument = new FileArgument('f', // Short identifier
         "ldifFile", // Long identifier
         true, // Is required
         1, // Only one occurrence
         "{path}", // Value placeholder
         "The path to the LDIF file containing the changes to process.",
         true, // File must exist
         true, // Parent must exist
         true, // Must be file
         false); // Must be directory
    ldifFileArgument.addLongIdentifier("ldif-file", true);
    parser.addArgument(ldifFileArgument);

    final LinkedHashSet<String> errorBehaviorAllowedValues =
         new LinkedHashSet<>(3);
    errorBehaviorAllowedValues.add(ERROR_BEHAVIOR_ATOMIC);
    errorBehaviorAllowedValues.add(ERROR_BEHAVIOR_ABORT_ON_ERROR);
    errorBehaviorAllowedValues.add(ERROR_BEHAVIOR_CONTINUE_ON_ERROR);
    errorBehaviorArgument = new StringArgument(null, // No short identifier
         "errorBehavior", // Long identifier
         true, // Is required
         1, // Only one occurrence
         "{atomic|abort-on-error|continue-on-error}", // Value placeholder
         "The behavior to exhibit if any errors are encountered during "+
              "processing.  The value must be one of 'atomic', " +
              "'abort-on-error', or 'continue-on-error'.",
         errorBehaviorAllowedValues);
    errorBehaviorArgument.addLongIdentifier("error-behavior", true);
    parser.addArgument(errorBehaviorArgument);
  }



  /**
   * Indicates whether this tool should default to interactively prompting for
   * the bind password if a password is required but no argument was provided
   * to indicate how to get the password.
   *
   * @return  {@code true} if this tool should default to interactively
   *          prompting for the bind password, or {@code false} if not.
   */
  @Override()
  protected boolean defaultToPromptForBindPassword()
  {
    return true;
  }



  /**
   * Indicates whether the LDAP-specific arguments should include alternate
   * versions of all long identifiers that consist of multiple words so that
   * they are available in both camelCase and dash-separated versions.
   *
   * @return  {@code true} if this tool should provide multiple versions of
   *          long identifiers for LDAP-specific arguments, or {@code false} if
   *          not.
   */
  @Override()
  protected boolean includeAlternateLongIdentifiers()
  {
    return true;
  }



  /**
   * Performs the core set of processing for this tool.
   *
   * @return  A result code that indicates whether the processing completed
   *          successfully.
   */
  @Override()
  public ResultCode doToolProcessing()
  {
    // Select the appropriate error behavior.
    final MultiUpdateErrorBehavior errorBehavior;
    final String errorBehaviorValue =
         StaticUtils.toLowerCase(errorBehaviorArgument.getValue());
    switch (errorBehaviorValue)
    {
      case ERROR_BEHAVIOR_ATOMIC:
        errorBehavior = MultiUpdateErrorBehavior.ATOMIC;
        break;
      case ERROR_BEHAVIOR_ABORT_ON_ERROR:
        errorBehavior = MultiUpdateErrorBehavior.ABORT_ON_ERROR;
        break;
      case ERROR_BEHAVIOR_CONTINUE_ON_ERROR:
        errorBehavior = MultiUpdateErrorBehavior.CONTINUE_ON_ERROR;
        break;
      default:
        err("Invalid error behavior value '", errorBehaviorValue,
             "'.  It must be one of ", ERROR_BEHAVIOR_ATOMIC, ", ",
             ERROR_BEHAVIOR_ABORT_ON_ERROR, ", or ",
             ERROR_BEHAVIOR_CONTINUE_ON_ERROR, ".");
        return ResultCode.PARAM_ERROR;
    }


    // Open the LDIF file and read all of the changes that it contains.
    final List<LDAPRequest> updateRequests = new ArrayList<>(10);
    try (LDIFReader ldifReader = new LDIFReader(ldifFileArgument.getValue()))
    {
      while (true)
      {
        final LDIFChangeRecord changeRecord = ldifReader.readChangeRecord(true);
        if (changeRecord == null)
        {
          break;
        }

        switch (changeRecord.getChangeType())
        {
          case ADD:
            updateRequests.add(
                 ((LDIFAddChangeRecord) changeRecord).toAddRequest());
            break;
          case DELETE:
            updateRequests.add(
                 ((LDIFDeleteChangeRecord) changeRecord).toDeleteRequest());
            break;
          case MODIFY:
            updateRequests.add(
                 ((LDIFModifyChangeRecord) changeRecord).toModifyRequest());
            break;
          case MODIFY_DN:
            updateRequests.add(
                 ((LDIFModifyDNChangeRecord) changeRecord).toModifyDNRequest());
            break;
          default:
            // This should never happen.
            err("Unsupported change record found in LDIF file '",
                 ldifFileArgument.getValue().getAbsolutePath(), ":");
            err(changeRecord.toLDIFString());
            return ResultCode.PARAM_ERROR;
        }
      }
    }
    catch (final Exception e)
    {
      err("An error occurred while trying to read from LDIF file '",
           ldifFileArgument.getValue().getAbsolutePath(), "':  ",
           StaticUtils.getExceptionMessage(e));
      return ResultCode.LOCAL_ERROR;
    }


    // Get a connection to the directory server.
    MultiUpdateExtendedResult multiUpdateResult;
    try (LDAPConnection connection = getConnection())
    {
      // Construct-the multi-update extended request.
      final MultiUpdateExtendedRequest multiUpdateRequest =
           new MultiUpdateExtendedRequest(errorBehavior, updateRequests);

      // Send th request and read the response.
      try
      {
        multiUpdateResult = (MultiUpdateExtendedResult)
             connection.processExtendedOperation(multiUpdateRequest);
      }
      catch (final LDAPException e)
      {
        try
        {
          final ExtendedResult genericExtendedResult =
               new ExtendedResult(e.toLDAPResult());
          multiUpdateResult =
               new MultiUpdateExtendedResult(genericExtendedResult);
        }
        catch (final LDAPException e2)
        {
          err("An error occurred while trying to process the multi-update ",
               "extended request, and that error result could not be ",
               "interpreted as a multi-update extended result.  The error was:",
               StaticUtils.getExceptionMessage(e));
          return e.getResultCode();
        }
      }
    }
    catch (final LDAPException e)
    {
      err("Unable to connect to the directory server:  ",
           StaticUtils.getExceptionMessage(e));
      return e.getResultCode();
    }


    // Write a summary of the processing that was performed.
    out("Multi-Update Result Code: ",
         String.valueOf(multiUpdateResult.getResultCode()));

    if (multiUpdateResult.getDiagnosticMessage() != null)
    {
      out("Multi-Update Diagnostic Message: ",
           multiUpdateResult.getResultCode());
    }

    switch (multiUpdateResult.getChangesApplied())
    {
      case ALL:
        out("All changes were successfully applied.");
        break;
      case PARTIAL:
        out("Only some of the changes were successfully applied.");
        break;
      case NONE:
        out("None of the changes were successfully applied.");
        break;
      default:
        err("Unexpected changesApplied value: ",
             multiUpdateResult.getChangesApplied().name());
        break;
    }

    out();


    // Iterate through the requests and results and display information about
    // each.
    final Iterator<LDAPRequest> requestIterator = updateRequests.iterator();
    final Iterator<ObjectPair<OperationType,LDAPResult>> resultIterator =
         multiUpdateResult.getResults().iterator();
    while (resultIterator.hasNext())
    {
      final LDAPRequest request = requestIterator.next();
      final LDAPResult result = resultIterator.next().getSecond();

      if (result.getResultCode() == ResultCode.SUCCESS)
      {
        switch (request.getOperationType())
        {
          case ADD:
            out("Successfully added ", ((AddRequest) request).getDN());
            break;
          case DELETE:
            out("Successfully deleted ", ((DeleteRequest) request).getDN());
            break;
          case MODIFY:
            out("Successfully modified ", ((ModifyRequest) request).getDN());
            break;
          case MODIFY_DN:
            out("Successfully renamed ", ((ModifyDNRequest) request).getDN());
            break;
        }
      }
      else
      {
        switch (request.getOperationType())
        {
          case ADD:
            out("Failed to add ", ((AddRequest) request).getDN());
            break;
          case DELETE:
            out("Failed to delete ", ((DeleteRequest) request).getDN());
            break;
          case MODIFY:
            out("Failed to modify ", ((ModifyRequest) request).getDN());
            break;
          case MODIFY_DN:
            out("Failed to rename ", ((ModifyDNRequest) request).getDN());
            break;
        }

        out("Result Code: ", String.valueOf(result.getResultCode()));
      }

      if (result.getDiagnosticMessage() != null)
      {
        out("Diagnostic Message: ", result.getDiagnosticMessage());
      }

      if (result.getMatchedDN() != null)
      {
        out("Matched DN: ", result.getMatchedDN());
      }

      if (result.getReferralURLs() != null)
      {
        for (final String url : result.getReferralURLs())
        {
          out("Referral URL: ", url);
        }
      }

      out();
    }


    // There may be additional requests that weren't processed.  If so, then
    // just indicate that they were not attempted.
    while (requestIterator.hasNext())
    {
      final LDAPRequest request = requestIterator.next();
        switch (request.getOperationType())
        {
          case ADD:
            out("Did not attempt to add ", ((AddRequest) request).getDN());
            break;
          case DELETE:
            out("Did not attempt to delete ",
                 ((DeleteRequest) request).getDN());
            break;
          case MODIFY:
            out("Did not attempt to modify ",
                 ((ModifyRequest) request).getDN());
            break;
          case MODIFY_DN:
            out("Did not attempt to rename ",
                 ((ModifyDNRequest) request).getDN());
            break;
        }
    }


    return multiUpdateResult.getResultCode();
  }



  /**
   * Retrieves a set of information that may be used to generate example usage
   * information.  Each element in the returned map should consist of a map
   * between an example set of arguments and a string that describes the
   * behavior of the tool when invoked with that set of arguments.
   *
   * @return  A set of information that may be used to generate example usage
   *          information.  It may be {@code null} or empty if no example usage
   *          information is available.
   */
  @Override()
  public LinkedHashMap<String[],String> getExampleUsages()
  {
    final LinkedHashMap<String[],String> examples = new LinkedHashMap<>(1);
    examples.put(
         new String[]
         {
           "--ldifFile", "changes.ldif",
           "--errorBehavior", "atomic"
         },
         "Uses the multi-update extended operation in an attempt to apply " +
              "all changes in the changes.ldif file as a single atomic unit.");

    return examples;
  }
}
