/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.zeppelin.realm;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

import com.google.common.base.Joiner;
import com.google.common.collect.Sets;
import com.google.gson.Gson;
import com.google.gson.JsonParseException;

import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.HttpStatus;
import org.apache.commons.httpclient.methods.PostMethod;
import org.apache.commons.httpclient.methods.StringRequestEntity;
import org.apache.commons.lang3.StringUtils;
import org.apache.shiro.authc.AccountException;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.zeppelin.notebook.repo.zeppelinhub.websocket.utils.ZeppelinhubUtils;
import org.apache.zeppelin.server.ZeppelinServer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A {@code Realm} implementation that uses Alfresco to authenticate users.
 *
 */
public class AlfrescoRealm extends AuthorizingRealm {

  private static final Logger LOG = LoggerFactory.getLogger(AlfrescoRealm.class);
  private static final String DEFAULT_ALFRESCO_URL = "http://localhost:8082";
  private static final String USER_LOGIN_API_ENDPOINT = "alfresco/service/api/login";
  private static final String JSON_CONTENT_TYPE = "application/json";
  private static final String UTF_8_ENCODING = "UTF-8";
  private static final AtomicInteger INSTANCE_COUNT = new AtomicInteger();

  private final HttpClient httpClient;
  private final Gson gson;

  private String alfrescoUrl;
  private String name;

  public AlfrescoRealm() {
    super();
    LOG.debug("Init Alfresco Realm");
    httpClient = new HttpClient();
    gson = new Gson();
    name = getClass().getName() + "_" + INSTANCE_COUNT.getAndIncrement();
  }

  @Override
  protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authToken)
      throws AuthenticationException {
    UsernamePasswordToken token = (UsernamePasswordToken) authToken;
    if (StringUtils.isBlank(token.getUsername())) {
      throw new AccountException("Empty usernames are not allowed by this realm.");
    }
    String loginPayload = createLoginPayload(token.getUsername(), token.getPassword());
    User user = authenticateUser(loginPayload);
    LOG.debug("{} successfully login via Alfresco", user.username);
    return new SimpleAuthenticationInfo(user.username, token.getPassword(), name);
  }
  
  @Override
  protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
    String username = (String) getAvailablePrincipal(principals);
    Set<String> roleNames = Sets.newHashSet(username);
    return new SimpleAuthorizationInfo(roleNames);
  }
  
  protected void onInit() {
    super.onInit();
  }
  
  /**
   * Setter of Alfresco URL, this will be called by Shiro based on alfrescoUrl property
   * in shiro.ini file.</p>
   * It will also perform a check of Alfresco url {@link #isAlfrescoUrlValid(String)}, 
   * if the url is not valid, the default Alfresco url will be used.
   * 
   * @param url
   */
  public void setAlfrescoUrl(String url) {
    if (StringUtils.isBlank(url)) {
      LOG.warn("Alfresco url is empty, setting up default url {}", DEFAULT_ALFRESCO_URL);
      alfrescoUrl = DEFAULT_ALFRESCO_URL;
    } else {
      alfrescoUrl = (isAlfrescoUrlValid(url) ? url : DEFAULT_ALFRESCO_URL);
      LOG.info("Setting up Alfresco url to {}", alfrescoUrl);
    }
  }

  /**
   * Send to Alfresco a login request based on the request body which is a JSON that contains 2 
   * fields "username" and "password".
   * 
   * @param requestBody JSON string of Alfresco payload.
   * @return Account object with username.
   * @throws AuthenticationException if fail to login.
   */
  protected User authenticateUser(String requestBody) {
    PostMethod post = new PostMethod(Joiner.on("/").join(alfrescoUrl, USER_LOGIN_API_ENDPOINT));
    String responseBody = StringUtils.EMPTY;
    String userSession = StringUtils.EMPTY;
    try {
      StringRequestEntity stringRequestEntity;
      stringRequestEntity = new StringRequestEntity(requestBody, JSON_CONTENT_TYPE, UTF_8_ENCODING);
      post.setRequestEntity(stringRequestEntity);
      int statusCode = httpClient.executeMethod(post);
      if (statusCode != HttpStatus.SC_OK) {
        LOG.error("Cannot login user, HTTP status code is {} instead on 200 (OK)", statusCode);
        post.releaseConnection();
        throw new AuthenticationException("Couldnt login to Alfresco. "
            + "Login or password incorrect");
      }
      responseBody = requestBody;
      post.releaseConnection();
      
    } catch (IOException e) {
      LOG.error("Cannot login user", e);
      throw new AuthenticationException(e.getMessage());
    }

    User account = null;
    try {
      account = gson.fromJson(responseBody, User.class);
    } catch (JsonParseException e) {
      LOG.error("Cannot deserialize Alfresco response to User instance", e);
      throw new AuthenticationException("Cannot login to Alfresco");
    }

    onLoginSuccess(account.username, userSession);

    return account;
  }

  /**
   * Create a JSON String that represent login payload.</p>
   * Payload will look like:
   * <code>
   *  {
   *   'username': 'userLogin',
   *   'password': 'userpassword'
   *  }
   * </code>
   * @param login
   * @param pwd
   * @return
   */
  protected String createLoginPayload(String login, char[] pwd) {
    StringBuilder sb = new StringBuilder("{\"username\":\"");
    return sb.append(login).append("\", \"password\":\"").append(pwd).append("\"}").toString();
  }

  /**
   * Perform a Simple URL check by using <code>URI(url).toURL()</code>.
   * If the url is not valid, the try-catch condition will catch the exceptions and return false,
   * otherwise true will be returned.
   * 
   * @param url
   * @return
   */
  protected boolean isAlfrescoUrlValid(String url) {
    boolean valid;
    try {
      new URI(url).toURL();
      valid = true;
    } catch (URISyntaxException | MalformedURLException e) {
      LOG.error("Alfresco url is not valid, default Alfresco url will be used.", e);
      valid = false;
    }
    return valid;
  }

  /**
   * Helper class that will be use to deserialize Alfresco response.
   */
  protected class User {
    public String username;
  }
  
  /**
   * TODO
  */
  public void onLoginSuccess(String username, String session) {
    //UserSessionContainer.instance.setSession(username, session);

    /* TODO(xxx): add proper roles */
    HashSet<String> userAndRoles = new HashSet<String>();
    userAndRoles.add(username);
    ZeppelinServer.notebookWsServer.broadcastReloadedNoteList(
        new org.apache.zeppelin.user.AuthenticationInfo(username), userAndRoles);

    //ZeppelinhubUtils.userLoginRoutine(username);
  }
  
  @Override
  public void onLogout(PrincipalCollection principals) {
    ZeppelinhubUtils.userLogoutRoutine((String) principals.getPrimaryPrincipal());
  }
}
