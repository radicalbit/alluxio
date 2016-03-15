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

import alluxio.Constants;

import com.google.common.base.Preconditions;

import org.apache.hadoop.security.UserGroupInformation;
import org.apache.thrift.transport.TTransport;
import org.apache.thrift.transport.TTransportFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.PrivilegedAction;

/**
 * A TransportFactory that wraps another one, but assumes a specified UGI before calling through.
 *
 * This is used on the server side to assume the server's Principal when accepting clients.
 *
 * Borrowed from Apache Hive 0.14
 */
public class TUGIAssumingTransportFactory extends TTransportFactory {

  private static final Logger LOG = LoggerFactory.getLogger(Constants.LOGGER_TYPE);

  private final UserGroupInformation mUgi;
  private final TTransportFactory mWrapped;

  /**
   * constructor.
   * @param wrapped wrapped
   * @param ugi mUgi
   */
  public TUGIAssumingTransportFactory(TTransportFactory wrapped, UserGroupInformation ugi) {
    Preconditions.checkNotNull(wrapped);
    Preconditions.checkNotNull(ugi);

    mWrapped = wrapped;
    mUgi = ugi;
  }

  @Override
  public TTransport getTransport(final TTransport trans) {
    return mUgi.doAs(new PrivilegedAction<TTransport>() {
      @Override
      public TTransport run() {

        LOG.debug("The current UGI for TUGIAssumingTransportFactory is {}", mUgi.getUserName());

        return mWrapped.getTransport(trans);
      }
    });
  }
}
