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

package alluxio;

import alluxio.util.SecurityUtils;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.security.UserGroupInformation;
import org.junit.Assert;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.security.PrivilegedExceptionAction;

/**
 * A utility class that lets program code run in a security context provided by the Hadoop security
 * user groups.
 *
 * The secure context will for example pick up authentication information from Kerberos.
 */
public final class HadoopSecurityTestUtils {

  private static final Logger LOG = LoggerFactory.getLogger(SecurityUtils.class);

  public static final String ORG_NAME = "EXAMPLE";
  public static final String ORG_DOMAIN = "COM";

  // load Hadoop configuration when loading the security utils.
  private static Configuration sHDCONF;

  private static Configuration getsHDCONF() {
    if (sHDCONF == null) {
      sHDCONF = new Configuration(false);
      sHDCONF.set("hadoop.security.authentication", "kerberos");
      sHDCONF.set("hadoop.security.auth_to_local", "RULE:[1:$1]\n" + "RULE:[2:$1]");
    }
    return sHDCONF;
  }

  private static boolean isSecurityEnabled() {
    UserGroupInformation.setConfiguration(getsHDCONF());
    return UserGroupInformation.isSecurityEnabled();
  }

  /**
   * run a method in a security context as login user.
   * @param runner the method to be run
   * @param <T> the return type
   * @return the result of the secure method
   * @throws IOException if something went wrong
   */
  public static <T> T runAsLoginUser(final AlluxioSecuredRunner<T> runner) throws IOException {

    if (!isSecurityEnabled()) {
      return runner.run();
    }

    UserGroupInformation.setConfiguration(sHDCONF);

    LOG.debug("login user {}", UserGroupInformation.getLoginUser());
    LOG.debug("current user {}", UserGroupInformation.getCurrentUser());

    UserGroupInformation ugi = UserGroupInformation.getLoginUser();
    if (!ugi.hasKerberosCredentials()) {
      LOG.error("Security is enabled but no Kerberos credentials have been found. "
          + "You may authenticate using the kinit command.");
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

  /**
   * run a method in a security context as current user.
   * @param runner the method to be run
   * @param <T> the return type
   * @return the result of the secure method
   * @throws IOException if something went wrong
   */
  public static <T> T runAsCurrentUser(final AlluxioSecuredRunner<T> runner) throws IOException {

    if (!isSecurityEnabled()) {
      return runner.run();
    }

    UserGroupInformation.setConfiguration(sHDCONF);

    LOG.debug("login user {}", UserGroupInformation.getLoginUser());
    LOG.debug("current user {}", UserGroupInformation.getCurrentUser());

    UserGroupInformation ugi = UserGroupInformation.getCurrentUser();
    if (!ugi.hasKerberosCredentials()) {
      LOG.error("Security is enabled but no Kerberos credentials have been found. "
              + "You may authenticate using the kinit command.");
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

  /**
   * run a method in a security context as current user.
   * @param runner the method to be run
   * @param <T> the return type
   * @return the result of the secure method
   * @throws IOException if something went wrong
   */
  public static <T> T runAs(UserGroupInformation ugi, final AlluxioSecuredRunner<T> runner)
      throws IOException {

    if (!isSecurityEnabled()) {
      System.out.println("security is not enabled");
      return runner.run();
    }

    LOG.debug("login user {}", UserGroupInformation.getLoginUser());
    LOG.debug("current user {}", UserGroupInformation.getCurrentUser());

    if (!ugi.hasKerberosCredentials()) {
      LOG.error("Security is enabled but no Kerberos credentials have been found. "
              + "You may authenticate using the kinit command.");
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

  /**
   * interface that holds a method run.
   * @param <T> the return type of run method
   */
  public interface AlluxioSecuredRunner<T> {
    /**
     * method to run.
     * @return anything
     * @throws IOException if something went wrong
     */
    T run() throws IOException;
  }

  /**
   * method that creates a keytab for test purpose.
   * @return the keytab file
   */
  public static File computeKeytabDir() {
    File targetDir = new File(System.getProperty("user.dir"), "target");
    Assert.assertTrue("Could not find Maven target directory: " + targetDir,
            targetDir.exists() && targetDir.isDirectory());

    // Create the directories: target/kerberos/keytabs
    File keytabDir = new File(new File(targetDir, "kerberos"), "keytabs");

    Assert.assertTrue(keytabDir.mkdirs() || keytabDir.isDirectory());

    return keytabDir;
  }

  /**
   * method that returnes a fully qualified kerberos principal given a primary part.
   * @param primary the primary part of a kerberos principal
   * @return the fully qualified kerberos principal
   */
  public static String qualifyUser(String primary) {
    return String.format("%s@%s.%s", primary, ORG_NAME, ORG_DOMAIN);
  }

  /**
   * Private constructor to prevent instantiation.
   */
  private HadoopSecurityTestUtils() {
    throw new RuntimeException();
  }
}
