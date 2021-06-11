package org.wso2.carbon.identity.oauth2.dao;

import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;

import java.util.List;
import java.util.Set;

public class CacheBackedAccessTokenDAO extends AbstractOAuthDAO implements AccessTokenDAO {

    @Override
    public void insertAccessToken(String accessToken, String consumerKey, AccessTokenDO accessTokenDO, String userStoreDomain) throws IdentityOAuth2Exception {

    }

    @Override
    public boolean insertAccessToken(String accessToken, String consumerKey, AccessTokenDO newAccessTokenDO, AccessTokenDO existingAccessTokenDO, String rawUserStoreDomain) throws IdentityOAuth2Exception {

        return false;
    }

    @Override
    public AccessTokenDO getLatestAccessToken(String consumerKey, AuthenticatedUser authzUser, String userStoreDomain, String scope, boolean includeExpiredTokens) throws IdentityOAuth2Exception {

        return null;
    }

    @Override
    public Set<AccessTokenDO> getAccessTokens(String consumerKey, AuthenticatedUser userName, String userStoreDomain, boolean includeExpired) throws IdentityOAuth2Exception {

        return null;
    }

    @Override
    public AccessTokenDO getAccessToken(String accessTokenIdentifier, boolean includeExpired) throws IdentityOAuth2Exception {

        return null;
    }

    @Override
    public Set<String> getAccessTokensByUser(AuthenticatedUser authenticatedUser) throws IdentityOAuth2Exception {

        return null;
    }

    @Override
    public Set<String> getActiveTokensByConsumerKey(String consumerKey) throws IdentityOAuth2Exception {

        return null;
    }

    @Override
    public Set<AccessTokenDO> getActiveAcessTokenDataByConsumerKey(String consumerKey) throws IdentityOAuth2Exception {

        return null;
    }

    @Override
    public Set<AccessTokenDO> getAccessTokensByTenant(int tenantId) throws IdentityOAuth2Exception {

        return null;
    }

    @Override
    public Set<AccessTokenDO> getAccessTokensOfUserStore(int tenantId, String userStoreDomain) throws IdentityOAuth2Exception {

        return null;
    }

    @Override
    public void revokeAccessTokens(String[] tokens) throws IdentityOAuth2Exception {

    }

    @Override
    public void revokeAccessTokensInBatch(String[] tokens) throws IdentityOAuth2Exception {

    }

    @Override
    public void revokeAccessTokensIndividually(String[] tokens) throws IdentityOAuth2Exception {

    }

    @Override
    public void revokeAccessToken(String tokenId, String userId) throws IdentityOAuth2Exception {

    }

    @Override
    public void invalidateAndCreateNewAccessToken(String oldAccessTokenId, String tokenState, String consumerKey, String tokenStateId, AccessTokenDO accessTokenDO, String userStoreDomain) throws IdentityOAuth2Exception {

    }

    @Override
    public void updateUserStoreDomain(int tenantId, String currentUserStoreDomain, String newUserStoreDomain) throws IdentityOAuth2Exception {

    }

    @Override
    public String getTokenIdByAccessToken(String token) throws IdentityOAuth2Exception {

        return null;
    }

    @Override
    public List<AccessTokenDO> getLatestAccessTokens(String consumerKey, AuthenticatedUser authzUser, String userStoreDomain, String scope, boolean includeExpiredTokens, int limit) throws IdentityOAuth2Exception {

        return null;
    }

    @Override
    public void updateAccessTokenState(String tokenId, String tokenState) throws IdentityOAuth2Exception {

    }
}
