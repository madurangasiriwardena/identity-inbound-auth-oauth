package org.wso2.carbon.identity.oauth.dao;

import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.oauth.IdentityOAuthAdminException;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;

import java.util.List;

/**
 * Data Access Layer for OAuth related operations.
 */
public interface OAuthAppDAO {

    void addOAuthApplication(OAuthAppDO consumerAppDO) throws IdentityOAuthAdminException;

    String[] addOAuthConsumer(String username, int tenantId, String userDomain) throws
            IdentityOAuthAdminException;

    OAuthAppDO[] getOAuthConsumerAppsOfUser(String username, int tenantId) throws IdentityOAuthAdminException;

    OAuthAppDO getAppInformation(String consumerKey) throws
            InvalidOAuthClientException, IdentityOAuth2Exception;

    OAuthAppDO getAppInformationByAppName(String appName) throws
            InvalidOAuthClientException, IdentityOAuth2Exception;

    void updateConsumerApplication(OAuthAppDO oauthAppDO) throws IdentityOAuthAdminException;

    void removeConsumerApplication(String consumerKey) throws IdentityOAuthAdminException;

    /**
     * Delete all consumer applications of a given tenant.
     *
     * @param tenantId Id of the tenant
     * @throws IdentityOAuthAdminException
     */
    void removeConsumerApplicationsByTenantId(int tenantId) throws IdentityOAuthAdminException;

    /**
     * Update the OAuth service provider name.
     *
     * @param appName     Service provider name.
     * @param consumerKey Consumer key.
     * @throws IdentityApplicationManagementException Identity Application Management Exception
     */
    void updateOAuthConsumerApp(String appName, String consumerKey)
            throws IdentityApplicationManagementException;

    /**
     * Update app name and owner in oauth client if the app owner is valid, Otherwise update only the app name.
     *
     * @param serviceProvider Service provider.
     * @param consumerKey     Consumer key of the Oauth app.
     * @throws IdentityApplicationManagementException Error while updating Oauth app details.
     * @throws IdentityOAuthAdminException            Error occurred while validating app owner.
     */
    void updateOAuthConsumerApp(ServiceProvider serviceProvider, String consumerKey)
            throws IdentityApplicationManagementException, IdentityOAuthAdminException;

    String getConsumerAppState(String consumerKey) throws IdentityOAuthAdminException;

    void updateConsumerAppState(String consumerKey, String state) throws
            IdentityApplicationManagementException;

    boolean isDuplicateApplication(String username, int tenantId, String userDomain, OAuthAppDO
            consumerAppDTO)
            throws IdentityOAuthAdminException;

    boolean isDuplicateConsumer(String consumerKey) throws IdentityOAuthAdminException;

    /**
     * Retrieves OIDC audience values configured for an oauth consumer app.
     *
     * @param tenantDomain application tenant domain
     * @param consumerKey  client ID
     * @return
     * @throws IdentityOAuth2Exception
     */
    List<String> getOIDCAudiences(String tenantDomain, String consumerKey) throws IdentityOAuth2Exception;

    /**
     * Remove Oauth consumer app related properties.
     *
     * @param tenantDomain application tenant domain
     * @param consumerKey  client ID
     * @throws IdentityOAuthAdminException
     */
    void removeOIDCProperties(String tenantDomain, String consumerKey) throws IdentityOAuthAdminException;
}
