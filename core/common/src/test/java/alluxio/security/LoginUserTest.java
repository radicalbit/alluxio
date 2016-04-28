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

package alluxio.security;

import alluxio.Configuration;
import alluxio.Constants;
import alluxio.HadoopSecurityTestUtils;
import alluxio.security.authentication.AuthType;

import org.apache.hadoop.minikdc.KerberosSecurityTestcase;
import org.apache.hadoop.security.UserGroupInformation;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.io.File;
import java.io.IOException;
import java.lang.reflect.Field;

/**
 * Unit test for {@link alluxio.security.LoginUser}.
 */
public final class LoginUserTest extends KerberosSecurityTestcase {

  /**
   * The exception expected to be thrown.
   */
  @Rule
  public ExpectedException mThrown = ExpectedException.none();

  /**
   * User reflection to reset the private static member sLoginUser in LoginUser.
   */
  @Before
  public void before() throws Exception {
    Field field = LoginUser.class.getDeclaredField("sLoginUser");
    field.setAccessible(true);
    field.set(null, null);
  }

  /**
   * Tests whether we can get login user with conf in SIMPLE mode.
   */
  @Test
  public void getSimpleLoginUserTest() throws Exception {
    Configuration conf = new Configuration();
    conf.set(Constants.SECURITY_AUTHENTICATION_TYPE, AuthType.SIMPLE.getAuthName());

    User loginUser = LoginUser.get(conf);

    Assert.assertNotNull(loginUser);
    Assert.assertEquals(loginUser.getName(), System.getProperty("user.name"));
  }

  /**
   * Tests whether we can get login user with conf in SIMPLE mode, when user name is provided by
   * the application through configuration.
   */
  @Test
  public void getSimpleLoginUserProvidedByAppTest() throws Exception {
    Configuration conf = new Configuration();
    conf.set(Constants.SECURITY_AUTHENTICATION_TYPE, AuthType.SIMPLE.getAuthName());
    conf.set(Constants.SECURITY_LOGIN_USERNAME, "alluxio-user");

    User loginUser = LoginUser.get(conf);

    Assert.assertNotNull(loginUser);
    Assert.assertEquals(loginUser.getName(), "alluxio-user");
  }

  /**
   * Tests whether we can get login user with conf in SIMPLE mode, when a user list is provided by
   * by the application through configuration.
   */
  @Test
  public void getSimpleLoginUserListProvidedByAppTest() throws Exception {
    Configuration conf = new Configuration();
    conf.set(Constants.SECURITY_AUTHENTICATION_TYPE, AuthType.SIMPLE.getAuthName());
    conf.set(Constants.SECURITY_LOGIN_USERNAME, "alluxio-user, superuser");

    User loginUser = LoginUser.get(conf);

    // The user list is considered as a single user name.
    Assert.assertNotNull(loginUser);
    Assert.assertEquals(loginUser.getName(), "alluxio-user, superuser");
  }

  /**
   * Tests whether we can get login user with conf in SIMPLE mode, when user name is set to an
   * empty string in the application configuration. In this case, login should return the OS user
   * instead of empty string.
   */
  @Test
  public void getSimpleLoginUserWhenNotProvidedByAppTest() throws Exception {
    Configuration conf = new Configuration();
    conf.set(Constants.SECURITY_AUTHENTICATION_TYPE, AuthType.SIMPLE.getAuthName());
    conf.set(Constants.SECURITY_LOGIN_USERNAME, "");

    User loginUser = LoginUser.get(conf);

    Assert.assertNotNull(loginUser);
    Assert.assertEquals(loginUser.getName(), System.getProperty("user.name"));
  }

  /**
   * Tests whether we can get login user with conf in CUSTOM mode.
   */
  @Test
  public void getCustomLoginUserTest() throws Exception {
    Configuration conf = new Configuration();
    conf.set(Constants.SECURITY_AUTHENTICATION_TYPE, AuthType.CUSTOM.getAuthName());

    User loginUser = LoginUser.get(conf);

    Assert.assertNotNull(loginUser);
    Assert.assertEquals(loginUser.getName(), System.getProperty("user.name"));
  }

  /**
   * Tests whether we can get login user with conf in CUSTOM mode, when user name is provided by
   * the application through configuration.
   */
  @Test
  public void getCustomLoginUserProvidedByAppTest() throws Exception {
    Configuration conf = new Configuration();
    conf.set(Constants.SECURITY_AUTHENTICATION_TYPE, AuthType.CUSTOM.getAuthName());
    conf.set(Constants.SECURITY_LOGIN_USERNAME, "alluxio-user");

    User loginUser = LoginUser.get(conf);

    Assert.assertNotNull(loginUser);
    Assert.assertEquals(loginUser.getName(), "alluxio-user");
  }

  /**
   * Tests whether we can get login user with conf in CUSTOM mode, when user name is set to an
   * empty string in the application configuration. In this case, login should return the OS user
   * instead of empty string.
   */
  @Test
  public void getCustomLoginUserWhenNotProvidedByAppTest() throws Exception {
    Configuration conf = new Configuration();
    conf.set(Constants.SECURITY_AUTHENTICATION_TYPE, AuthType.CUSTOM.getAuthName());
    conf.set(Constants.SECURITY_LOGIN_USERNAME, "");

    User loginUser = LoginUser.get(conf);

    Assert.assertNotNull(loginUser);
    Assert.assertEquals(loginUser.getName(), System.getProperty("user.name"));
  }

  /**
   * Tests whether we can get login user with conf in KERBEROS mode, when user
   * is not authenticated.
   */
  @Test
  public void getKerberosLoginUserNotProvided() throws Exception {
    Configuration conf = new Configuration();
    conf.set(Constants.SECURITY_AUTHENTICATION_TYPE, AuthType.KERBEROS.getAuthName());

    mThrown.expect(IOException.class);
    mThrown.expectMessage("Fail to login");

    LoginUser.get(conf);
  }

  /**
   * Tests whether we can get login user with conf in KERBEROS mode, when user
   * is authenticated.
   */
  @Test
  public void getKerberosLoginUserProvided() throws Exception {

    File keyTabDir = HadoopSecurityTestUtils.computeKeytabDir();

    final String testPrincipal = "test";

    final File testKeytab = new File(keyTabDir, testPrincipal + ".keytab");

    getKdc().createPrincipal(testKeytab, testPrincipal);

    org.apache.hadoop.conf.Configuration hConf = new org.apache.hadoop.conf.Configuration();
    hConf.set("hadoop.security.authentication", "kerberos");
    hConf.set("hadoop.security.auth_to_local", "RULE:[1:$1]\n" + "RULE:[2:$1]");
    UserGroupInformation.setConfiguration(hConf);

    UserGroupInformation masterUgi = UserGroupInformation.loginUserFromKeytabAndReturnUGI(
        HadoopSecurityTestUtils.qualifyUser(testPrincipal), testKeytab.getAbsolutePath());

    HadoopSecurityTestUtils.runAs(masterUgi,
        new HadoopSecurityTestUtils.AlluxioSecuredRunner<Void>() {
          @Override
          public Void run() throws IOException {

            Configuration conf = new Configuration();
            conf.set(Constants.SECURITY_AUTHENTICATION_TYPE, AuthType.KERBEROS.getAuthName());

            User loginUser = LoginUser.get(conf);

            Assert.assertNotNull(loginUser);
            Assert.assertEquals(loginUser.getName(), testPrincipal);

            return null;
          }
        });
  }

  /**
   * Tests whether we can get exception when getting a login user in non-security mode.
   */
  @Test
  public void securityEnabledTest() throws Exception {
    // TODO(dong): add Kerberos in the white list when it is supported.
    // throw exception when AuthType is not "SIMPLE", or "CUSTOM"
    Configuration conf = new Configuration();
    conf.set(Constants.SECURITY_AUTHENTICATION_TYPE, AuthType.NOSASL.getAuthName());

    mThrown.expect(UnsupportedOperationException.class);
    mThrown.expectMessage("User is not supported in NOSASL mode");
    LoginUser.get(conf);
  }
}
