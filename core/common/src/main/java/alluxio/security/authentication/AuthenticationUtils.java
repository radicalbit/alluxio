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
import alluxio.security.LoginUser;
import alluxio.util.network.NetworkAddressUtils;

import org.apache.hadoop.security.HadoopKerberosName;
import org.apache.hadoop.security.SaslRpcServer;
import org.apache.hadoop.security.SecurityUtil;
import org.apache.hadoop.security.UserGroupInformation;
import org.apache.thrift.transport.TTransportFactory;
import org.apache.thrift.transport.TFramedTransport;
import org.apache.thrift.transport.TSaslServerTransport;
import org.apache.thrift.transport.TTransport;
import org.apache.thrift.transport.TSocket;
import org.apache.thrift.transport.TSaslClientTransport;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.HashMap;
import java.util.Map;

import javax.annotation.concurrent.ThreadSafe;
import javax.security.sasl.Sasl;
//import javax.security.sasl.SaslException;

/**
 * This class provides factory methods for authentication in Alluxio. Based on different
 * authentication types specified in Alluxio configuration, it provides corresponding Thrift class
 * for authenticated connection between Client and Server.
 */
@ThreadSafe
public final class AuthenticationUtils {

  private static final Logger LOG = LoggerFactory.getLogger(Constants.LOGGER_TYPE);

  /**
   * For server side, this method returns a {@link TTransportFactory} based on the auth type. It is
   * used as one argument to build a Thrift {@link org.apache.thrift.server.TServer}. If the auth
   * type is not supported or recognized, an {@link UnsupportedOperationException} is thrown.
   *
   * @param conf Alluxio Configuration
   * @return a corresponding TTransportFactory
   * @throws IOException if building a TransportFactory fails
   */
  public static TTransportFactory getServerTransportFactory(Configuration conf)
      throws IOException {
    AuthType authType = conf.getEnum(Constants.SECURITY_AUTHENTICATION_TYPE, AuthType.class);
    switch (authType) {
      case NOSASL:
        return new TFramedTransport.Factory(
            (int) conf.getBytes(Constants.THRIFT_FRAME_SIZE_BYTES_MAX));
      case SIMPLE: // intended to fall through
      case CUSTOM:
        return PlainSaslUtils.getPlainServerTransportFactory(authType, conf);
      case KERBEROS: {

        String masterPrincipal = conf.get(Constants.MASTER_PRINCIPAL_KEY);

        String principal = SecurityUtil.getServerPrincipal(masterPrincipal,
            InetAddress.getLocalHost().getCanonicalHostName());
        HadoopKerberosName name = new HadoopKerberosName(principal);
        String primary = name.getServiceName();
        String instance = name.getHostName();

        UserGroupInformation serverUser = UserGroupInformation.getLoginUser();
        LOG.info("Current user: {}", serverUser);

        // Use authorization and confidentiality
        Map<String, String> saslProperties = new HashMap<String, String>();
        saslProperties.put(Sasl.QOP, "auth-conf");

        // Creating the server definition
        TSaslServerTransport.Factory saslTransportFactory = new TSaslServerTransport.Factory();
        saslTransportFactory.addServerDefinition("GSSAPI", // tell SASL to use GSSAPI, which
                                                           // supports Kerberos
            "", // primary, // kerberos primary for server - "myprincipal" in
                // myprincipal/my.server.com@MY.REALM
            "", // instance, // kerberos instance for server - "my.server.com" in
                // myprincipal/my.server.com@MY.REALM
            saslProperties, // Properties set, above
            new SaslRpcServer.SaslGssCallbackHandler()); // Ensures that authenticated user is the
                                                         // same as the authorized user

        // Make sure the TTransportFactory is performing a UGI.doAs
//        TTransportFactory ugiTransportFactory =
        return new TUGIAssumingTransportFactory(saslTransportFactory, serverUser);

      }
      default:
        throw new UnsupportedOperationException("getServerTransportFactory: Unsupported "
            + "authentication type: " + authType.getAuthName());
    }
  }

  /**
   * Creates a transport per the connection options. Supported transport options are:
   * {@link AuthType#NOSASL}, {@link AuthType#SIMPLE}, {link@ AuthType#CUSTOM},
   * {@link AuthType#KERBEROS}. With NOSASL as input, an unmodified TTransport is returned; with
   * SIMPLE/CUSTOM as input, a PlainClientTransport is returned; KERBEROS is not supported
   * currently. If the auth type is not supported or recognized, an
   * {@link UnsupportedOperationException} is thrown.
   *
   * @param conf Alluxio Configuration
   * @param serverAddress the server address which clients will connect to
   * @return a TTransport for client
   * @throws IOException if building a TransportFactory fails or user login fails
   */
  public static TTransport getClientTransport(Configuration conf, InetSocketAddress serverAddress)
      throws IOException {
    AuthType authType = conf.getEnum(Constants.SECURITY_AUTHENTICATION_TYPE, AuthType.class);
    TTransport tTransport = AuthenticationUtils.createTSocket(serverAddress,
        conf.getInt(Constants.SECURITY_AUTHENTICATION_SOCKET_TIMEOUT_MS));
    switch (authType) {
      case NOSASL:
        return new TFramedTransport(tTransport,
            (int) conf.getBytes(Constants.THRIFT_FRAME_SIZE_BYTES_MAX));
      case SIMPLE: // intended to fall through
      case CUSTOM:
        String username = LoginUser.get(conf).getName();
        return PlainSaslUtils.getPlainClientTransport(username, "noPassword", tTransport);
      case KERBEROS: {

        Map<String, String> saslProperties = new HashMap<String, String>();
        // Use authorization and confidentiality
        saslProperties.put(Sasl.QOP, "auth-conf");

        UserGroupInformation currentUser = UserGroupInformation.getCurrentUser();

        // SASL client transport -- does the Kerberos lifting for us
        TSaslClientTransport saslTransport = new TSaslClientTransport("GSSAPI", // tell SASL to use
                                                                                // GSSAPI, which
                                                                                // supports Kerberos
            null, // authorizationid - null
            null, // kerberos primary for server - "myprincipal" in
                  // myprincipal/my.server.com@MY.REALM
            null, // kerberos instance for server - "my.server.com" in
                  // myprincipal/my.server.com@MY.REALM
            saslProperties, // Properties set, above
            null, // callback handler - null
            AuthenticationUtils.createTSocket(serverAddress,
                conf.getInt(Constants.SECURITY_AUTHENTICATION_SOCKET_TIMEOUT_MS))); // underlying
                                                                                    // transport

        // Make sure the transport is opened as the user we logged in as
        return new TUGIAssumingTransport(saslTransport, currentUser);
      }
      default:
        throw new UnsupportedOperationException(
            "getClientTransport: Unsupported authentication type: " + authType.getAuthName());
    }
  }

  /**
   * Creates a new Thrift socket what will connect to the given address.
   *
   * @param address The given address to connect
   * @param timeoutMs the timeout in milliseconds
   * @return An unconnected socket
   */
  public static TSocket createTSocket(InetSocketAddress address, int timeoutMs) {
    return new TSocket(NetworkAddressUtils.getFqdnHost(address), address.getPort(), timeoutMs);
  }

  private AuthenticationUtils() {} // prevent instantiation
}
