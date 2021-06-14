package org.wso2.carbon.identity.oauth2.dao;

import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.cache.CacheEntry;
import org.wso2.carbon.identity.oauth.cache.OAuthCache;
import org.wso2.carbon.identity.oauth.cache.OAuthCacheKey;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.token.OauthTokenIssuer;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import java.util.Collections;
import java.util.List;
import java.util.Set;

import static org.wso2.carbon.identity.oauth.common.OAuthConstants.TokenBindings.NONE;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE;

public class CacheBackedAccessTokenDAO extends AbstractOAuthDAO implements AccessTokenDAO {

    private AccessTokenDAO accessTokenDAO = new AccessTokenDAOImpl();
    private Boolean isHashDisabled = OAuth2Util.isHashDisabled();
    protected boolean cacheEnabled = OAuthCache.getInstance().isEnabled();
    private static final Log log = LogFactory.getLog(CacheBackedAccessTokenDAO.class);

    @Override
    public void insertAccessToken(String accessToken, String consumerKey, AccessTokenDO accessTokenDO, String userStoreDomain) throws IdentityOAuth2Exception {

        accessTokenDAO.insertAccessToken(accessToken, consumerKey, accessTokenDO, userStoreDomain);
    }

    @Override
    public boolean insertAccessToken(String accessToken, String consumerKey, AccessTokenDO newAccessTokenDO, AccessTokenDO existingAccessTokenDO, String rawUserStoreDomain) throws IdentityOAuth2Exception {

        boolean responseFromDAO = accessTokenDAO.insertAccessToken(accessToken, consumerKey, newAccessTokenDO, existingAccessTokenDO,
                rawUserStoreDomain);

        if (isHashDisabled && cacheEnabled) {
            AccessTokenDO tokenToCache = AccessTokenDO.clone(newAccessTokenDO);
            OauthTokenIssuer oauthTokenIssuer;
            // If usePersistedAccessTokenAlias is enabled then in the DB the
            // access token alias taken from the OauthTokenIssuer's getAccessTokenHash
            // method is set as the token.

            try {
                oauthTokenIssuer = OAuth2Util.getOAuthTokenIssuerForOAuthApp(consumerKey);

            } catch (InvalidOAuthClientException e) {
                throw new IdentityOAuth2Exception(
                        "Error while retrieving oauth issuer for the app with clientId: " + consumerKey, e);
            }

            if (oauthTokenIssuer.usePersistedAccessTokenAlias()) {
                try {
                    String persistedTokenIdentifier =
                            oauthTokenIssuer.getAccessTokenHash(newAccessTokenDO.getAccessToken());
                    tokenToCache.setAccessToken(persistedTokenIdentifier);
                } catch (OAuthSystemException e) {
                    if (log.isDebugEnabled()) {
                        if (IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.ACCESS_TOKEN)) {
                            log.debug("Token issuer: " + oauthTokenIssuer.getClass() + " was tried and" +
                                    " failed to parse the received token: " + tokenToCache.getAccessToken(), e);
                        } else {
                            log.debug("Token issuer: " + oauthTokenIssuer.getClass() + " was tried and" +
                                    " failed to parse the received token.", e);
                        }
                    }
                }
            }

            OAuthCacheKey cacheKey = getOAuthCacheKey(OAuth2Util.buildScopeString(newAccessTokenDO.getScope()),
                    tokenToCache.getConsumerKey(),
                    tokenToCache.getAuthzUser().toString(), OAuth2Util.getAuthenticatedIDP(tokenToCache.getAuthzUser()),
                    getTokenBindingReference(tokenToCache));
            OAuthCache.getInstance().addToCache(cacheKey, tokenToCache);
            if (log.isDebugEnabled()) {
                log.debug("Access token was added to OAuthCache with cache key : " + cacheKey.getCacheKeyString());
            }

            // Adding AccessTokenDO to improve validation performance
            OAuth2Util.addTokenDOtoCache(newAccessTokenDO);
        }

        return responseFromDAO;
    }

    private OAuthCacheKey getOAuthCacheKey(String scope, String consumerKey, String authorizedUser,
                                           String authenticatedIDP) {

        String cacheKeyString = OAuth2Util.buildCacheKeyStringForToken(consumerKey, scope, authorizedUser,
                authenticatedIDP);
        return new OAuthCacheKey(cacheKeyString);
    }

    private OAuthCacheKey getOAuthCacheKey(String scope, String consumerKey, String authorizedUser,
                                           String authenticatedIDP, String tokenBindingType) {

        String cacheKeyString = OAuth2Util.buildCacheKeyStringForToken(consumerKey, scope, authorizedUser,
                authenticatedIDP, tokenBindingType);
        return new OAuthCacheKey(cacheKeyString);
    }

    /**
     * Get token binding reference.
     *
     * @param accessTokenDO accessTokenDO.
     * @return token binding reference.
     */
    private String getTokenBindingReference(AccessTokenDO accessTokenDO) {

        if (accessTokenDO.getTokenBinding() == null || StringUtils
                .isBlank(accessTokenDO.getTokenBinding().getBindingReference())) {
            return NONE;
        }
        return accessTokenDO.getTokenBinding().getBindingReference();
    }

    @Override
    public AccessTokenDO getLatestAccessToken(String consumerKey, AuthenticatedUser authzUser, String userStoreDomain, String scope, boolean includeExpiredTokens) throws IdentityOAuth2Exception {

        AccessTokenDO latestAccessToken = null;
        String authenticatedIDP = OAuth2Util.getAuthenticatedIDP(authzUser);

        OAuthCacheKey cacheKey = getOAuthCacheKey(scope, consumerKey, authzUser.toString(), authenticatedIDP);

        if (cacheEnabled) {
            latestAccessToken = getExistingTokenFromCache(cacheKey, consumerKey, scope, authzUser.toString());
        }

        if (latestAccessToken != null) {
            return latestAccessToken;
        }

        latestAccessToken = accessTokenDAO.getLatestAccessToken(consumerKey, authzUser, userStoreDomain, scope, includeExpiredTokens);

        if (latestAccessToken != null) {
            if (log.isDebugEnabled()) {
                if (IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.ACCESS_TOKEN)) {
                    log.debug("Retrieved latest access token(hashed): " + DigestUtils.sha256Hex(latestAccessToken
                            .getAccessToken()) + " in state: " + latestAccessToken.getTokenState() + " for client Id: " +
                            consumerKey + " user: " + authzUser + " and scope: " + scope + " from db");
                } else {
                    log.debug("Retrieved latest access token for client Id: " + consumerKey + " user: " +
                            authzUser + " and scope: " + scope + " from db");
                }
            }

            long expireTime = getAccessTokenExpiryTimeMillis(latestAccessToken);
            if (TOKEN_STATE_ACTIVE.equals(latestAccessToken.getTokenState()) && expireTime != 0 && cacheEnabled) {
                // Active token retrieved from db, adding to cache if cacheEnabled

                OAuthCache.getInstance().addToCache(cacheKey, latestAccessToken);
                // Adding AccessTokenDO to improve validation performance
                OAuth2Util.addTokenDOtoCache(latestAccessToken);
            }
        }

        return latestAccessToken;
    }

    private AccessTokenDO getExistingTokenFromCache(OAuthCacheKey cacheKey, String consumerKey, String scope,
                                                    String authorizedUser) {

        AccessTokenDO existingTokenBean = null;
        CacheEntry cacheEntry = OAuthCache.getInstance().getValueFromCache(cacheKey);
        if (cacheEntry instanceof AccessTokenDO) {
            existingTokenBean = (AccessTokenDO) cacheEntry;
            if (log.isDebugEnabled()) {
                if (IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.ACCESS_TOKEN)) {
                    log.debug("Retrieved active access token(hashed): " + DigestUtils.sha256Hex(existingTokenBean
                            .getAccessToken()) + " in state: " + existingTokenBean.getTokenState() + " for client " +
                            "Id: " + consumerKey + ", user: " + authorizedUser + " and scope: " + scope + " from" +
                            " cache.");

                } else {
                    log.debug("Retrieved active access token in state: " + existingTokenBean.getTokenState() + " for " +
                            "" + "client Id: " + consumerKey + ", user: " + authorizedUser + " and scope: " + scope +
                            " from cache.");
                }
            }
//            if (getAccessTokenExpiryTimeMillis(existingTokenBean) == 0) {
//                // Token is expired. Clear it from cache.
//                removeFromCache(cacheKey, consumerKey, existingTokenBean);
//            }
        }
        return existingTokenBean;
    }

    private AccessTokenDO getExistingTokenFromCache(OAuthCacheKey cacheKey, String consumerKey, String authorizedUser,
                                                    String scope, String tokenBindingReference) {

        AccessTokenDO existingToken = null;
        CacheEntry cacheEntry = OAuthCache.getInstance().getValueFromCache(cacheKey);
        if (cacheEntry instanceof AccessTokenDO) {
            existingToken = (AccessTokenDO) cacheEntry;
            if (log.isDebugEnabled() && IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.ACCESS_TOKEN)) {
                log.debug("Retrieved active access token(hashed): " + DigestUtils
                        .sha256Hex(existingToken.getAccessToken()) + " in the state: " + existingToken.getTokenState()
                        + " for client Id: " + consumerKey + ", user: " + authorizedUser + " ,scope: " + scope
                        + " and token binding reference: " + tokenBindingReference + " from cache");
            }
            if (getAccessTokenExpiryTimeMillis(existingToken) == 0) {
                // Token is expired. Clear it from cache.
                removeFromCache(cacheKey, consumerKey, existingToken);
                return null;
            }
        }
        return existingToken;
    }

    private static long getAccessTokenExpiryTimeMillis(AccessTokenDO tokenBean) {

        // Consider both access and refresh expiry time
        long expireTimeMillis = OAuth2Util.getTokenExpireTimeMillis(tokenBean);

        if (log.isDebugEnabled()) {
            if (IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.ACCESS_TOKEN)) {
                if (expireTimeMillis > 0) {
                    log.debug("Access Token(hashed): " + DigestUtils.sha256Hex(tokenBean.getAccessToken()) + " is " +
                            "still valid. Remaining time: " + expireTimeMillis + " ms");
                } else {
                    log.debug("Infinite lifetime Access Token(hashed) " + DigestUtils.sha256Hex(tokenBean
                            .getAccessToken()) + " found");
                }
            } else {
                if (expireTimeMillis > 0) {
                    log.debug("Valid access token is found for client: " + tokenBean.getConsumerKey() + ". Remaining " +
                            "time: " + expireTimeMillis + " ms");
                } else {
                    log.debug("Infinite lifetime Access Token found for client: " + tokenBean.getConsumerKey());
                }
            }
        }
        return expireTimeMillis;
    }

    public AccessTokenDO getLatestAccessToken(String consumerKey, AuthenticatedUser authzUser, String userStoreDomain,
                                              String scope, String tokenBindingReference, boolean includeExpiredTokens) throws IdentityOAuth2Exception {

        OAuthCacheKey cacheKey = getOAuthCacheKey(scope,
                consumerKey,
                authzUser.toString(), OAuth2Util.getAuthenticatedIDP(authzUser),
                tokenBindingReference);

        AccessTokenDO existingToken
                = getExistingTokenFromCache(cacheKey, consumerKey, authzUser.toString(), scope, tokenBindingReference);

        if (existingToken != null) {
            return existingToken;
        }

        existingToken = accessTokenDAO.getLatestAccessToken(consumerKey, authzUser, userStoreDomain,
                scope, tokenBindingReference, includeExpiredTokens);

        if (existingToken != null) {
            if (log.isDebugEnabled()) {
                if (IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.ACCESS_TOKEN)) {
                    log.debug("Retrieved latest access token(hashed): " + DigestUtils.sha256Hex
                            (existingToken.getAccessToken()) + " in the state: " + existingToken.getTokenState() +
                            " for client Id: " + consumerKey + " user: " + authzUser +
                            " and scope: " + scope + " from db");
                } else {
                    log.debug("Retrieved latest access token for client Id: " + consumerKey + " user: " +
                            authzUser + " and scope: " + scope + " from db");
                }
            }
            long expireTime = getAccessTokenExpiryTimeMillis(existingToken);
            if (TOKEN_STATE_ACTIVE.equals(existingToken.getTokenState()) && expireTime != 0) {
                // Active token retrieved from db, adding to cache if cacheEnabled
                OAuthCache.getInstance().addToCache(cacheKey, existingToken);
                if (log.isDebugEnabled()) {
                    log.debug("Access token was added to OAuthCache with cache key : " + cacheKey.getCacheKeyString());
                }

                // Adding AccessTokenDO to improve validation performance
                OAuth2Util.addTokenDOtoCache(existingToken);
            }
        }
        return existingToken;
    }

    private void removeFromCache(OAuthCacheKey cacheKey, String consumerKey, AccessTokenDO existingAccessTokenDO) {

        OAuthCache.getInstance().clearCacheEntry(cacheKey);
        if (log.isDebugEnabled()) {
            if (IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.ACCESS_TOKEN)) {
                log.debug("Access token(hashed) " + DigestUtils.sha256Hex(existingAccessTokenDO
                        .getAccessToken()) + " is expired. Therefore cleared it from cache and marked" +
                        " it as expired in database");
            } else {
                log.debug("Existing access token for client: " + consumerKey + " is expired. " +
                        "Therefore cleared it from cache and marked it as expired in database");
            }
        }
    }

    public void storeTokenToSessionMapping(String sessionContextIdentifier, String tokenId, int tenantId)
            throws IdentityOAuth2Exception {

        accessTokenDAO.storeTokenToSessionMapping(sessionContextIdentifier, tokenId, tenantId);
    }

    @Override
    public Set<AccessTokenDO> getAccessTokens(String consumerKey, AuthenticatedUser userName, String userStoreDomain, boolean includeExpired) throws IdentityOAuth2Exception {

        return accessTokenDAO.getAccessTokens(consumerKey, userName, userStoreDomain, includeExpired);
    }

    @Override
    public AccessTokenDO getAccessToken(String accessTokenIdentifier, boolean includeExpired) throws IdentityOAuth2Exception {

        return accessTokenDAO.getAccessToken(accessTokenIdentifier, includeExpired);
    }

    @Override
    public Set<String> getAccessTokensByUser(AuthenticatedUser authenticatedUser) throws IdentityOAuth2Exception {

        return accessTokenDAO.getAccessTokensByUser(authenticatedUser);
    }

    @Override
    public Set<AccessTokenDO> getAccessTokensByUserForOpenidScope(AuthenticatedUser authenticatedUser)
            throws IdentityOAuth2Exception {

        return accessTokenDAO.getAccessTokensByUserForOpenidScope(authenticatedUser);
    }

    @Override
    public Set<String> getActiveTokensByConsumerKey(String consumerKey) throws IdentityOAuth2Exception {

        return accessTokenDAO.getActiveTokensByConsumerKey(consumerKey);
    }

    @Override
    public Set<AccessTokenDO> getActiveAcessTokenDataByConsumerKey(String consumerKey) throws IdentityOAuth2Exception {

        return accessTokenDAO.getActiveAcessTokenDataByConsumerKey(consumerKey);
    }

    @Override
    public Set<AccessTokenDO> getAccessTokensByTenant(int tenantId) throws IdentityOAuth2Exception {

        return accessTokenDAO.getAccessTokensByTenant(tenantId);
    }

    @Override
    public Set<AccessTokenDO> getAccessTokensOfUserStore(int tenantId, String userStoreDomain) throws IdentityOAuth2Exception {

        return accessTokenDAO.getAccessTokensOfUserStore(tenantId, userStoreDomain);
    }

    @Override
    public void revokeAccessTokens(String[] tokens) throws IdentityOAuth2Exception {

        accessTokenDAO.revokeAccessTokens(tokens);
    }

    @Override
    public void revokeAccessTokensInBatch(String[] tokens) throws IdentityOAuth2Exception {

        accessTokenDAO.revokeAccessTokensInBatch(tokens);
    }

    @Override
    public void revokeAccessTokensIndividually(String[] tokens) throws IdentityOAuth2Exception {

        accessTokenDAO.revokeAccessTokensIndividually(tokens);
    }

    public void revokeAccessTokens(String[] tokens, boolean isHashedToken) throws IdentityOAuth2Exception {
        accessTokenDAO.revokeAccessTokens( tokens,  isHashedToken);
    }

    public void revokeAccessTokensInBatch(String[] tokens, boolean isHashedToken) throws IdentityOAuth2Exception {
        accessTokenDAO.revokeAccessTokensInBatch(tokens,  isHashedToken);
    }

    public void revokeAccessTokensIndividually(String[] tokens, boolean isHashedToken) throws IdentityOAuth2Exception {
        accessTokenDAO.revokeAccessTokensIndividually( tokens,  isHashedToken);
    }

    @Override
    public void revokeAccessToken(String tokenId, String userId) throws IdentityOAuth2Exception {

        accessTokenDAO.revokeAccessToken(tokenId, userId);
    }

    @Override
    public void invalidateAndCreateNewAccessToken(String oldAccessTokenId, String tokenState, String consumerKey, String tokenStateId, AccessTokenDO accessTokenDO, String userStoreDomain) throws IdentityOAuth2Exception {

        accessTokenDAO.invalidateAndCreateNewAccessToken(oldAccessTokenId, tokenState, consumerKey, tokenStateId,
                accessTokenDO, userStoreDomain);
    }

    @Override
    public void updateUserStoreDomain(int tenantId, String currentUserStoreDomain, String newUserStoreDomain) throws IdentityOAuth2Exception {

        accessTokenDAO.updateUserStoreDomain(tenantId, currentUserStoreDomain, newUserStoreDomain);
    }

    @Override
    public String getTokenIdByAccessToken(String token) throws IdentityOAuth2Exception {

        return accessTokenDAO.getTokenIdByAccessToken(token);
    }

    @Override
    public List<AccessTokenDO> getLatestAccessTokens(String consumerKey, AuthenticatedUser authzUser, String userStoreDomain, String scope, boolean includeExpiredTokens, int limit) throws IdentityOAuth2Exception {

        return accessTokenDAO.getLatestAccessTokens(consumerKey, authzUser, userStoreDomain, scope, includeExpiredTokens, limit);
    }

    @Override
    public void updateAccessTokenState(String tokenId, String tokenState) throws IdentityOAuth2Exception {

        accessTokenDAO.updateAccessTokenState(tokenId, tokenState);
    }

    public List<AccessTokenDO> getLatestAccessTokens(String consumerKey, AuthenticatedUser authzUser,
                                                     String userStoreDomain, String scope, String tokenBindingReference,
                                                     boolean includeExpiredTokens, int limit)
            throws IdentityOAuth2Exception {

        return accessTokenDAO.getLatestAccessTokens(consumerKey, authzUser,
                userStoreDomain, scope, tokenBindingReference, includeExpiredTokens, limit);
    }

    public Set<AccessTokenDO> getActiveTokenSetWithTokenIdByConsumerKeyForOpenidScope(String consumerKey)
            throws IdentityOAuth2Exception {

        return accessTokenDAO.getActiveTokenSetWithTokenIdByConsumerKeyForOpenidScope(consumerKey);
    }

    /**
     * Retrieve the active access tokens of a given user with a given access token binding reference.
     *
     * @param user       authenticated user
     * @param bindingRef access token binding reference
     * @return set of active access objects
     * @throws IdentityOAuth2Exception if the retrieval process fails
     */
    public Set<AccessTokenDO> getAccessTokensByBindingRef(AuthenticatedUser user, String bindingRef) throws
            IdentityOAuth2Exception {

        return accessTokenDAO.getAccessTokensByBindingRef(user, bindingRef);
    }

    public Set<AccessTokenDO> getAccessTokensByBindingRef(String bindingRef) throws IdentityOAuth2Exception {

        return accessTokenDAO.getAccessTokensByBindingRef(bindingRef);
    }

    public String getAccessTokenByTokenId(String tokenId) throws IdentityOAuth2Exception {

        return accessTokenDAO.getAccessTokenByTokenId(tokenId);
    }
}
