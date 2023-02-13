/*
 * Copyright (c) 2019, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.wso2.carbon.identity.oauth.functions;

import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang.NotImplementedException;
import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.mgt.model.AccessTokenConfiguration;
import org.wso2.carbon.identity.application.mgt.model.IdTokenConfiguration;
import org.wso2.carbon.identity.application.mgt.model.OAuth2PKCEConfiguration;
import org.wso2.carbon.identity.application.mgt.model.OIDCLogoutConfiguration;
import org.wso2.carbon.identity.application.mgt.model.OpenIDConnectConfiguration;
import org.wso2.carbon.identity.application.mgt.model.RefreshTokenConfiguration;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;

import java.util.List;
import java.util.Optional;

import static org.wso2.carbon.identity.application.mgt.functions.Utils.setIfNotNull;

/**
 * Converts OpenIDConnectConfiguration api model to OAuthConsumerAppDTO.
 */
public class ApiModelToOAuthConsumerApp implements ApiModelToOAuthConsumerAppFunction<OpenIDConnectConfiguration,
        OAuthAppDO> {

    @Override
    public OAuthAppDO apply(String appName, OpenIDConnectConfiguration oidcModel) {

        OAuthAppDO authAppDO = new OAuthAppDO();

        authAppDO.setApplicationName(appName);
        authAppDO.setOauthConsumerKey(oidcModel.getClientId());
        authAppDO.setOauthConsumerSecret(oidcModel.getClientSecret());

        authAppDO.setCallbackUrl(getCallbackUrl(oidcModel.getCallbackURLs()));

        authAppDO.setOauthVersion(OAuthConstants.OAuthVersions.VERSION_2);

        authAppDO.setGrantTypes(getGrantTypes(oidcModel));
        authAppDO.setScopeValidators(getScopeValidators(oidcModel));

        authAppDO.setBypassClientCredentials(oidcModel.getPublicClient());
        authAppDO.setRequestObjectSignatureValidationEnabled(oidcModel.getValidateRequestObjectSignature());
        authAppDO.setState(oidcModel.getState().toString());

        // TODO There is no way to get the app owner at the moment. Hence hard coding it for now to continue the flow.
        AuthenticatedUser appOwner = new AuthenticatedUser();
        appOwner.setUserName("admin");
        appOwner.setTenantDomain("carbon.super");
        appOwner.setUserStoreDomain("PRIMARY");
        authAppDO.setAppOwner(appOwner);

        updateAllowedOrigins(authAppDO, oidcModel.getAllowedOrigins());
        updatePkceConfigurations(authAppDO, oidcModel.getPkce());
        updateAccessTokenConfiguration(authAppDO, oidcModel.getAccessToken());
        updateRefreshTokenConfiguration(authAppDO, oidcModel.getRefreshToken());
        updateIdTokenConfiguration(authAppDO, oidcModel.getIdToken());
        updateOidcLogoutConfiguration(authAppDO, oidcModel.getLogout());

        return authAppDO;
    }

    private String getGrantTypes(OpenIDConnectConfiguration oidcModel) {

        if (CollectionUtils.isEmpty(oidcModel.getGrantTypes())) {
            return null;
        } else {
            return StringUtils.join(oidcModel.getGrantTypes(), " ");
        }
    }

    private void updateOidcLogoutConfiguration(OAuthAppDO consumerAppDTO, OIDCLogoutConfiguration logout) {

        if (logout != null) {
            consumerAppDTO.setBackChannelLogoutUrl(logout.getBackChannelLogoutUrl());
            consumerAppDTO.setFrontchannelLogoutUrl(logout.getFrontChannelLogoutUrl());
        }
    }

    private void updateIdTokenConfiguration(OAuthAppDO consumerAppDTO, IdTokenConfiguration idToken) {

        if (idToken != null) {
            setIfNotNull(idToken.getExpiryInSeconds(), consumerAppDTO::setIdTokenExpiryTime);
            consumerAppDTO.setAudiences(Optional.ofNullable(idToken.getAudience())
                    .map(audiences -> audiences.toArray(new String[0]))
                    .orElse(new String[0])
            );

            if (idToken.getEncryption() != null) {
                boolean idTokenEncryptionEnabled = isIdTokenEncryptionEnabled(idToken);
                consumerAppDTO.setIdTokenEncryptionEnabled(idTokenEncryptionEnabled);
                if (idTokenEncryptionEnabled) {
                    consumerAppDTO.setIdTokenEncryptionAlgorithm(idToken.getEncryption().getAlgorithm());
                    consumerAppDTO.setIdTokenEncryptionMethod(idToken.getEncryption().getMethod());
                }
            }
        }
    }

    private boolean isIdTokenEncryptionEnabled(IdTokenConfiguration idToken) {

        return idToken.getEncryption().getEnabled() != null && idToken.getEncryption().getEnabled();
    }

    private void updateRefreshTokenConfiguration(OAuthAppDO consumerAppDTO,
                                                 RefreshTokenConfiguration refreshToken) {

        if (refreshToken != null) {
            consumerAppDTO.setRefreshTokenExpiryTime(refreshToken.getExpiryInSeconds());
            String renewRefreshToken = refreshToken.getRenewRefreshToken() != null ?
                    String.valueOf(refreshToken.getRenewRefreshToken()) : null;
            consumerAppDTO.setRenewRefreshTokenEnabled(renewRefreshToken);
        }
    }

    private void updateAllowedOrigins(OAuthAppDO consumerAppDTO, List<String> allowedOrigins) {

        // CORS are updated directly at the REST API level through the CORS Management OSGi service.
    }

    private void updateAccessTokenConfiguration(OAuthAppDO oAuthAppDO,
                                                AccessTokenConfiguration accessToken) {

        if (accessToken != null) {
            oAuthAppDO.setTokenType(accessToken.getType());
            oAuthAppDO.setUserAccessTokenExpiryTime(accessToken.getUserAccessTokenExpiryInSeconds());
            oAuthAppDO.setApplicationAccessTokenExpiryTime(accessToken.getApplicationAccessTokenExpiryInSeconds());
            oAuthAppDO.setTokenBindingType(accessToken.getBindingType());
            if (accessToken.getRevokeTokensWhenIDPSessionTerminated() != null) {
                oAuthAppDO.setTokenRevocationWithIDPSessionTerminationEnabled(accessToken
                        .getRevokeTokensWhenIDPSessionTerminated());
            } else {
                oAuthAppDO.setTokenRevocationWithIDPSessionTerminationEnabled(false);
            }
            if (accessToken.getValidateTokenBinding() != null) {
                oAuthAppDO.setTokenBindingValidationEnabled(accessToken.getValidateTokenBinding());
            } else {
                oAuthAppDO.setTokenBindingValidationEnabled(false);
            }
        }
    }

    private void updatePkceConfigurations(OAuthAppDO oAuthAppDO, OAuth2PKCEConfiguration pkce) {

        if (pkce != null) {
            oAuthAppDO.setPkceMandatory(pkce.getMandatory());
            oAuthAppDO.setPkceSupportPlain(pkce.getSupportPlainTransformAlgorithm());
        }
    }

    private String[] getScopeValidators(OpenIDConnectConfiguration oidcModel) {

        return Optional.ofNullable(oidcModel.getScopeValidators())
                .map(validators -> validators.toArray(new String[0]))
                .orElse(new String[0]);
    }

    private String getCallbackUrl(List<String> callbackURLs) {

        if (CollectionUtils.isNotEmpty(callbackURLs)) {
            // We can't support multiple callback URLs at the moment. So we need to send a server error.
            if (callbackURLs.size() > 1) {
                throw new NotImplementedException("Multiple callbacks for OAuth2 are not supported yet. " +
                        "Please use regex to define multiple callbacks.");
            } else if (callbackURLs.size() == 1) {
                return callbackURLs.get(0);
            } else {
                return null;
            }
        } else {
            return null;
        }
    }
}
