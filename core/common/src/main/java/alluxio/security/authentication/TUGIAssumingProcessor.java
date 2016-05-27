/*
 * The Alluxio Open Foundation licenses this work under the Apache License, version 2.0
 * (the "License"). You may not use this work except in compliance with the License, which is
 * available at www.apache.org/licenses/LICENSE-2.0
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied, as more fully set forth in the License.
 *
 * See the NOTICE file distributed with this work for information regarding copyright ownership.
 */

package alluxio.security.authentication;

import alluxio.Constants;

import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.security.UserGroupInformation;
import org.apache.thrift.TException;
import org.apache.thrift.TProcessor;
import org.apache.thrift.protocol.TProtocol;
import org.apache.thrift.transport.TSaslServerTransport;
import org.apache.thrift.transport.TTransport;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.security.PrivilegedExceptionAction;

import javax.security.sasl.SaslServer;

/**
 * Processor that pulls the SaslServer object out of the transport, and assumes the remote user's
 * UGI before calling through to the original processor.
 *
 * This is used on the server side to set the UGI for each specific call.
 *
 * Lifted from Apache Hive 0.14
 */
public class TUGIAssumingProcessor implements TProcessor {
  private static final Logger LOG = LoggerFactory.getLogger(Constants.LOGGER_TYPE);
  final TProcessor mWrapped;

  /**
   * creates a processor that wraps another.
   * @param wrapped the wrapped processor
   */
  public TUGIAssumingProcessor(TProcessor wrapped) {
    mWrapped = wrapped;
  }

  @Override
  public boolean process(final TProtocol inProt, final TProtocol outProt) throws TException {
    System.err.println("inside process");
    TTransport trans = inProt.getTransport();
    if (!(trans instanceof TSaslServerTransport)) {
      throw new TException("Unexpected non-SASL transport " + trans.getClass());
    }
    TSaslServerTransport saslTrans = (TSaslServerTransport) trans;
    SaslServer saslServer = saslTrans.getSaslServer();
    String authId = saslServer.getAuthorizationID();
    String endUser = authId;

    UserGroupInformation clientUgi = null;
    try {
      System.err.println("################ ==> endUser " + endUser);
      System.err.println("################ ==> UserGroupInformation.getLoginUser() "
          + UserGroupInformation.getLoginUser());
      clientUgi =
          UserGroupInformation.createProxyUser(endUser, UserGroupInformation.getLoginUser());
      final String remoteUser = clientUgi.getShortUserName();
      System.err.println("Executing action as {} " + clientUgi);
      LOG.debug("Executing action as {}", clientUgi);
      return clientUgi.doAs(new PrivilegedExceptionAction<Boolean>() {
        @Override
        public Boolean run() {
          try {
            System.err.println(
                "################ ==> clientUgi.doAs UserGroupInformation.getCurrentUser() "
                    + UserGroupInformation.getCurrentUser());
            System.err
                .println("################ ==> clientUgi.doAs UserGroupInformation.getLoginUser() "
                    + UserGroupInformation.getLoginUser());
            return mWrapped.process(inProt, outProt);
          } catch (TException te) {
            te.printStackTrace();
            throw new RuntimeException(te);
          } catch (IOException e) {
            e.printStackTrace();
            throw new RuntimeException(e);
          }
        }
      });
    } catch (RuntimeException rte) {

      Throwable cause = rte.getCause();
      if (cause instanceof TException) {
        LOG.error("Failed to invoke mWrapped processor", cause);
        throw (TException) cause;
      }
      throw rte;
    } catch (InterruptedException | IOException e) {
      LOG.error("Failed to invoke mWrapped processor", e);
      throw new RuntimeException(e);
    } finally {
      if (clientUgi != null) {
        try {
          FileSystem.closeAllForUGI(clientUgi);
        } catch (IOException exception) {
          LOG.error("Could not clean up file-system handles for UGI: {}", clientUgi, exception);
        }
      }
    }
  }
}
