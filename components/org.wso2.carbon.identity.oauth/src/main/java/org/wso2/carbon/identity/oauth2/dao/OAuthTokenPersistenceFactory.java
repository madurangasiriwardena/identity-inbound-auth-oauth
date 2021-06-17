/*
 *
 *   Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *   WSO2 Inc. licenses this file to you under the Apache License,
 *   Version 2.0 (the "License"); you may not use this file except
 *   in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing,
 *   software distributed under the License is distributed on an
 *   "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *   KIND, either express or implied.  See the License for the
 *   specific language governing permissions and limitations
 *   under the License.
 * /
 */

package org.wso2.carbon.identity.oauth2.dao;

import org.wso2.carbon.identity.openidconnect.dao.CacheBackedScopeClaimMappingDAOImpl;
import org.wso2.carbon.identity.openidconnect.dao.RequestObjectDAO;
import org.wso2.carbon.identity.openidconnect.dao.v2.RequestObjectDAOImpl;
import org.wso2.carbon.identity.openidconnect.dao.ScopeClaimMappingDAO;
import org.wso2.carbon.identity.oauth2.dao.v2.AccessTokenDAOImpl;
import org.wso2.carbon.identity.oauth2.dao.v2.TokenManagementDAOImpl;
import org.wso2.carbon.identity.oauth2.dao.v2.AuthorizationCodeDAOImpl;
import org.wso2.carbon.identity.oauth2.dao.v2.TokenBindingMgtDAOImpl;

/**
 * OAUth token persistence factory.
 */
public class OAuthTokenPersistenceFactory {

    private static OAuthTokenPersistenceFactory factory = new OAuthTokenPersistenceFactory();
    private AuthorizationCodeDAO authorizationCodeDAO;
    private AccessTokenDAO tokenDAO;
    private OAuthScopeDAO scopeDAO;
    private TokenManagementDAO managementDAO;
    private RequestObjectDAO requestObjectDAO;
    private ScopeClaimMappingDAO scopeClaimMappingDAO;
    private TokenBindingMgtDAO tokenBindingMgtDAO;
    private OAuthUserConsentedScopesDAO oauthUserConsentedScopesDAO;

    public OAuthTokenPersistenceFactory() {

        this.authorizationCodeDAO = new AuthorizationCodeDAOImpl();
        this.tokenDAO = new AccessTokenDAOImpl();
        this.scopeDAO = new OAuthScopeDAOImpl();
        this.managementDAO = new TokenManagementDAOImpl();
        this.requestObjectDAO = new RequestObjectDAOImpl();
        this.scopeClaimMappingDAO = new CacheBackedScopeClaimMappingDAOImpl();
        this.tokenBindingMgtDAO = new TokenBindingMgtDAOImpl();
        this.oauthUserConsentedScopesDAO = new OAuthUserConsentedScopesDAOImpl();
    }

    public static OAuthTokenPersistenceFactory getInstance() {

        return factory;
    }

    public AuthorizationCodeDAO getAuthorizationCodeDAO() {

        return authorizationCodeDAO;
    }

    public AccessTokenDAO getAccessTokenDAO() {

        return tokenDAO;
    }

    public OAuthScopeDAO getOAuthScopeDAO() {

        return scopeDAO;
    }

    public TokenManagementDAO getTokenManagementDAO() {

        return managementDAO;
    }

    public RequestObjectDAO getRequestObjectDAO() {

        return requestObjectDAO;
    }

    public ScopeClaimMappingDAO getScopeClaimMappingDAO() {

        return scopeClaimMappingDAO;
    }

    public TokenBindingMgtDAO getTokenBindingMgtDAO() {

        return tokenBindingMgtDAO;
    }

    public OAuthUserConsentedScopesDAO getOAuthUserConsentedScopesDAO() {

        return oauthUserConsentedScopesDAO;
    }
}
