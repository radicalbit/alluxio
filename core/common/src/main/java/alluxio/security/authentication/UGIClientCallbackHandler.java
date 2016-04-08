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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.AuthorizeCallback;

/**
 * A client side callback to put application provided username/password into SASL transport.
 */
public final class UGIClientCallbackHandler implements CallbackHandler {

  private static final Logger LOG = LoggerFactory.getLogger(Constants.LOGGER_TYPE);

  @Override
  public void handle(Callback[] callbacks) throws UnsupportedCallbackException {
    AuthorizeCallback ac = null;
    for (Callback callback : callbacks) {
      if (callback instanceof AuthorizeCallback) {
        ac = (AuthorizeCallback) callback;
      } else {
        throw new UnsupportedCallbackException(callback, "Unrecognized SASL GSSAPI Callback");
      }
    }
    if (ac != null) {
      String authid = ac.getAuthenticationID();
      String authzid = ac.getAuthorizationID();
      if (authid.equals(authzid)) {
        ac.setAuthorized(true);
      } else {
        ac.setAuthorized(false);
      }
      if (ac.isAuthorized()) {
        if (LOG.isDebugEnabled()) {
          LOG.debug(
              "SASL server GSSAPI callback: setting " + "canonicalized client ID: " + authzid);
        }
        ac.setAuthorizedID(authzid);

        AuthenticatedClientUser.set(ac.getAuthorizedID());
      }
    }
  }
}
