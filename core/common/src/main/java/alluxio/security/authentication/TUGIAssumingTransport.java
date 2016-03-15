/*
 * The Alluxio Open Foundation licenses this work under the Apache License, version 2.0
 * (the “License”). You may not use this work except in compliance with the License, which is
 * available at www.apache.org/licenses/LICENSE-2.0
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied, as more fully set forth in the License.
 *
 * See the NOTICE file distributed with this work for information regarding copyright ownership.
 */

package alluxio.security.authentication;

import org.apache.hadoop.security.UserGroupInformation;
import org.apache.thrift.transport.TTransport;
import org.apache.thrift.transport.TTransportException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.security.PrivilegedExceptionAction;

/**
 * The Thrift SASL transports call Sasl.createSaslServer and Sasl.createSaslClient inside open().
 * So, we need to assume the correct UGI when the transport is opened so that the SASL mechanisms
 * have access to the right principal. This transport wraps the Sasl transports to set up the right
 * UGI context for open().
 *
 * This is used on the client side, where the API explicitly opens a transport to the server.
 *
 * Lifted from Apache Hive 0.14
 */
public class TUGIAssumingTransport extends TFilterTransport {
  private static final Logger log = LoggerFactory.getLogger(TUGIAssumingTransport.class);
  protected UserGroupInformation mUgi;

  public TUGIAssumingTransport(TTransport wrapped, UserGroupInformation mUgi) {
    super(wrapped);
    mUgi = mUgi;
  }

  @Override
  public void open() throws TTransportException {
    try {

      UserGroupInformation currentUser = UserGroupInformation.getCurrentUser();
      log.info("Current user: {}", currentUser);

      mUgi.doAs(new PrivilegedExceptionAction<Void>() {
        @Override
        public Void run() {
          try {

            UserGroupInformation currentUser = UserGroupInformation.getCurrentUser();
            log.info("Current user: {}", currentUser);

            getWrapped().open();
          } catch (TTransportException tte) {
            // Wrap the transport exception in an RTE, since UGI.doAs() then goes
            // and unwraps this for us out of the doAs block. We then unwrap one
            // more time in our catch clause to get back the TTE. (ugh)
            throw new RuntimeException(tte);
          } catch (IOException e) {
            e.printStackTrace();
          }
          return null;
        }
      });
    } catch (IOException ioe) {
      throw new RuntimeException("Received an ioe we never threw!", ioe);
    } catch (InterruptedException ie) {
      throw new RuntimeException("Received an ie we never threw!", ie);
    } catch (RuntimeException rte) {
      if (rte.getCause() instanceof TTransportException) {
        throw (TTransportException) rte.getCause();
      } else {
        throw rte;
      }
    }
  }
}
