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

import alluxio.Configuration;
import alluxio.Constants;
import alluxio.util.network.NetworkAddressUtils;

import org.apache.hadoop.security.HadoopKerberosName;
import org.apache.hadoop.security.SaslRpcServer;
import org.apache.hadoop.security.SecurityUtil;
import org.apache.hadoop.security.UserGroupInformation;

import com.google.common.base.Preconditions;
import org.apache.thrift.transport.TSaslClientTransport;
import org.apache.thrift.transport.TSaslServerTransport;
import org.apache.thrift.transport.TTransport;
import org.apache.thrift.transport.TTransportFactory;
import org.apache.thrift.transport.TSocket;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.security.Security;
import java.util.HashMap;
import java.util.Map;

import javax.annotation.concurrent.ThreadSafe;
import javax.security.sasl.Sasl;
import javax.security.sasl.SaslException;

/**
 * If authentication type is {@link AuthType#SIMPLE} or {@link AuthType#CUSTOM}, this is the default
 * transport provider which uses Sasl transport.
 */
@ThreadSafe
public final class UGITransportProvider implements TransportProvider {
  static {
    Security.addProvider(new PlainSaslServerProvider());
  }

  private static final Logger LOG = LoggerFactory.getLogger(Constants.LOGGER_TYPE);

  /** Timeout for socket in ms. */
  private int mSocketTimeoutMs;
  /** Configuration. */
  private Configuration mConfiguration;

  /**
   * Constructor for transport provider with {@link AuthType#SIMPLE} or {@link AuthType#CUSTOM}.
   *
   * @param conf Alluxio configuration
   */
  public UGITransportProvider(Configuration conf) {
    mConfiguration = Preconditions.checkNotNull(conf);
    mSocketTimeoutMs = conf.getInt(Constants.SECURITY_AUTHENTICATION_SOCKET_TIMEOUT_MS);
  }

  @Override
  public TTransport getClientTransport(InetSocketAddress serverAddress) throws IOException {
    String masterPrincipal = mConfiguration.get(Constants.MASTER_PRINCIPAL_KEY);

    String principal = SecurityUtil.getServerPrincipal(masterPrincipal,
        InetAddress.getLocalHost().getCanonicalHostName());
    HadoopKerberosName name = new HadoopKerberosName(principal);
    String primary = name.getServiceName();
    String instance = name.getHostName();

    LOG.debug("CLIENT TRANSPORT primary instance {} {}", primary, instance);

    Map<String, String> saslProperties = new HashMap<String, String>();
    // Use authorization and confidentiality
    saslProperties.put(Sasl.QOP, "auth-conf");

    UserGroupInformation currentUser = UserGroupInformation.getCurrentUser();

    // SASL client transport -- does the Kerberos lifting for us
    TSaslClientTransport saslTransport = new TSaslClientTransport("GSSAPI", // tell SASL to use
        // GSSAPI, which
        // supports Kerberos
        null, // authorizationid - null
        primary, // kerberos primary for server - "myprincipal" in
        // myprincipal/my.server.com@MY.REALM
        instance, // kerberos instance for server - "my.server.com" in
        // myprincipal/my.server.com@MY.REALM
        saslProperties, // Properties set, above
        null, // callback handler - null
        new TSocket(NetworkAddressUtils.getFqdnHost(serverAddress), serverAddress.getPort(),
                mSocketTimeoutMs));
            // transport

    // Make sure the transport is opened as the user we logged in as
    return new TUGIAssumingTransport(saslTransport, currentUser);
  }

  // // TODO(binfan): make this private and use whitebox to access this method in test
  // /**
  // * Gets a PLAIN mechanism transport for client side.
  // *
  // * @param username User Name of PlainClient
  // * @param password Password of PlainClient
  // * @param serverAddress Address of the server
  // * @return Wrapped transport with PLAIN mechanism
  // * @throws SaslException if an AuthenticationProvider is not found
  // */
  // public TTransport getClientTransport(String username, String password,
  // InetSocketAddress serverAddress) throws SaslException {
  // TTransport wrappedTransport =
  // TransportProviderUtils.createThriftSocket(serverAddress, mSocketTimeoutMs);
  // return new TSaslClientTransport(PlainSaslServerProvider.MECHANISM, null, null, null,
  // new HashMap<String, String>(), new PlainSaslClientCallbackHandler(username, password),
  // wrappedTransport);
  // }

  @Override
  public TTransportFactory getServerTransportFactory() throws SaslException {

    try {

      String masterPrincipal = mConfiguration.get(Constants.MASTER_PRINCIPAL_KEY);

      String principal = SecurityUtil.getServerPrincipal(masterPrincipal,
          InetAddress.getLocalHost().getCanonicalHostName());
      HadoopKerberosName name = new HadoopKerberosName(principal);
      String primary = name.getServiceName();
      String instance = name.getHostName();

      LOG.debug("SERVER TRANSPORT primary instance {} {}", primary, instance);

      UserGroupInformation serverUser = UserGroupInformation.getLoginUser();
      LOG.info("Current user: {}", serverUser);

      // Use authorization and confidentiality
      Map<String, String> saslProperties = new HashMap<String, String>();
      saslProperties.put(Sasl.QOP, "auth-conf");

      // Creating the server definition
      TSaslServerTransport.Factory saslTransportFactory = new TSaslServerTransport.Factory();
      saslTransportFactory.addServerDefinition("GSSAPI", // tell SASL to use GSSAPI, which
          // supports Kerberos
          primary, // primary, // kerberos primary for server - "myprincipal" in
          // myprincipal/my.server.com@MY.REALM
          instance, // instance, // kerberos instance for server - "my.server.com" in
          // myprincipal/my.server.com@MY.REALM
          saslProperties, // Properties set, above
          new SaslRpcServer.SaslGssCallbackHandler()); // Ensures that authenticated user is the
      // same as the authorized user

      // Make sure the TTransportFactory is performing a UGI.doAs
      // TTransportFactory ugiTransportFactory =
      return new TUGIAssumingTransportFactory(saslTransportFactory, serverUser);
    } catch (IOException e) {
      throw new SaslException(e.getMessage(), e);
    }
  }
}
