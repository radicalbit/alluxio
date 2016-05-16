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
import org.apache.hadoop.security.SecurityUtil;
import org.apache.hadoop.security.UserGroupInformation;

import com.google.common.base.Preconditions;
import org.apache.thrift.transport.TSaslClientTransport;
import org.apache.thrift.transport.TSaslServerTransport;
import org.apache.thrift.transport.TTransport;
import org.apache.thrift.transport.TTransportFactory;
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
 * If authentication type is {@link AuthType#KERBEROS}, this is the transport provider which uses
 * Sasl transport with Kerberos.
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
  public TTransport getClientTransport(InetSocketAddress serverAddress,
      NetworkAddressUtils.ServiceType serviceType) throws IOException {

    String principalName;

    switch (serviceType) {
      case MASTER_RPC: {
        principalName = mConfiguration.get(Constants.MASTER_PRINCIPAL_KEY);
        break;
      }
      case WORKER_RPC: {
        principalName = mConfiguration.get(Constants.WORKER_PRINCIPAL_KEY);
        break;
      }
      default:
        throw new SaslException("invalid serviceType");
    }

    String principal = SecurityUtil.getServerPrincipal(principalName,
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
        TransportProviderUtils.createThriftSocket(serverAddress, mSocketTimeoutMs));
    // transport

    // Make sure the transport is opened as the user we logged in as
    return new TUGIAssumingTransport(saslTransport, currentUser);
  }

  @Override
  public TTransportFactory getServerTransportFactory(NetworkAddressUtils.ServiceType serviceType)
      throws SaslException {
    try {

      String principalName;

      switch (serviceType) {
        case MASTER_RPC: {
          principalName = mConfiguration.get(Constants.MASTER_PRINCIPAL_KEY);
          break;
        }
        case WORKER_RPC: {
          principalName = mConfiguration.get(Constants.WORKER_PRINCIPAL_KEY);
          break;
        }
        default:
          throw new SaslException("invalid serviceType");
      }

      String principal = SecurityUtil.getServerPrincipal(principalName,
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
          new UGIClientCallbackHandler()); // Ensures that authenticated user is the
      // same as the authorized user

      // Make sure the TTransportFactory is performing a UGI.doAs
      // TTransportFactory ugiTransportFactory =
      return new TUGIAssumingTransportFactory(saslTransportFactory, serverUser);
    } catch (IOException e) {
      throw new SaslException(e.getMessage(), e);
    }
  }
}
