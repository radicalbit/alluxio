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

package alluxio.underfs.hdfs;
import org.apache.hadoop.conf.Configuration;
import alluxio.util.SecurityUtils;
import org.apache.hadoop.security.UserGroupInformation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.security.PrivilegedExceptionAction;

/**
 * A utility class that lets program code run in a security context provided by the
 * Hadoop security user groups.
 *
 * The secure context will for example pick up authentication information from Kerberos.
 */
public final class HadoopSecurityUtils {

  private static final Logger LOG = LoggerFactory.getLogger(SecurityUtils.class);

  // load Hadoop configuration when loading the security utils.
  private static Configuration hdConf = new Configuration();


  private static boolean isSecurityEnabled() {
    UserGroupInformation.setConfiguration(hdConf);
    return UserGroupInformation.isSecurityEnabled();
  }

  public static <T> T runSecured(final AlluxioSecuredRunner<T> runner) throws IOException {

    if (!isSecurityEnabled()){
      return runner.run();
    }

    UserGroupInformation.setConfiguration(hdConf);
    UserGroupInformation ugi = UserGroupInformation.getCurrentUser();
    if (!ugi.hasKerberosCredentials()) {
      LOG.error("Security is enabled but no Kerberos credentials have been found. " +
              "You may authenticate using the kinit command.");
    }
    try {
      return ugi.doAs(new PrivilegedExceptionAction<T>() {
        @Override
        public T run() throws IOException {
          return runner.run();
        }
      });
    } catch (InterruptedException e) {
      throw new IOException(e);
    }
  }

  public interface AlluxioSecuredRunner<T> {
    T run() throws IOException;
  }

  /**
   * Private constructor to prevent instantiation.
   */
  private HadoopSecurityUtils() {
    throw new RuntimeException();
  }
}
