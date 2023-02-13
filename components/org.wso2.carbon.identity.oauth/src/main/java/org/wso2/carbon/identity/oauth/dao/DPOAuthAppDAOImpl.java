package org.wso2.carbon.identity.oauth.dao;

import com.hazelcast.com.fasterxml.jackson.core.JsonProcessingException;
import com.hazelcast.com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpEntity;
import org.apache.http.HttpHeaders;
import org.apache.http.HttpHost;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.AuthCache;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.protocol.HttpClientContext;
import org.apache.http.impl.auth.BasicScheme;
import org.apache.http.impl.client.BasicAuthCache;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.util.EntityUtils;
import org.json.JSONArray;
import org.json.JSONObject;
import org.json.JSONTokener;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.mgt.model.OpenIDConnectConfiguration;
import org.wso2.carbon.identity.oauth.IdentityOAuthAdminException;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.functions.ApiModelToOAuthConsumerApp;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * This class is used to retrieve OAuth application information from the control plane.
 */
public class DPOAuthAppDAOImpl implements OAuthAppDAO {

    private static final Log LOG = LogFactory.getLog(DPOAuthAppDAOImpl.class);
    private static final String CP_BASE_URL = "https://localhost:9443";

    @Override
    public void addOAuthApplication(OAuthAppDO consumerAppDO) throws IdentityOAuthAdminException {

    }

    @Override
    public String[] addOAuthConsumer(String username, int tenantId, String userDomain)
            throws IdentityOAuthAdminException {

        return new String[0];
    }

    @Override
    public OAuthAppDO[] getOAuthConsumerAppsOfUser(String username, int tenantId) throws IdentityOAuthAdminException {

        return new OAuthAppDO[0];
    }

    @Override
    public OAuthAppDO getAppInformation(String consumerKey)
            throws InvalidOAuthClientException, IdentityOAuth2Exception {

        String tenantDomain = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain();
        OAuthAppDO oAuthAppDO = getOAuthApp(consumerKey, tenantDomain);
        return oAuthAppDO;
    }

    private OAuthAppDO getOAuthApp(String clientId, String tenantDomain)
            throws IdentityOAuth2Exception {

        String url = String.format(
                    CP_BASE_URL + "/t/%s/api/server/v1/applications?filter=clientId+eq+%s&limit=2&offset=0",
                    tenantDomain, clientId);

        String filteredList = callControlPlane(url);
        JSONObject jsonResponse = new JSONObject(new JSONTokener(filteredList));
        JSONArray applications = jsonResponse.getJSONArray("applications");
        if (applications.length() != 1) {
            throw new IdentityOAuth2Exception("Could not find a unique application for client id: " +
                    clientId);
        }

        JSONObject filteredApplication = (JSONObject) applications.get(0);
        String applicationId = filteredApplication.getString("id");
        String applicationName = filteredApplication.getString("name");
        OAuthAppDO oAuthAppDO = getOAuthAppInfo(tenantDomain, applicationName, applicationId);
        return oAuthAppDO;
    }

    private OAuthAppDO getOAuthAppInfo(String tenantDomain, String applicationName, String applicationId)
            throws IdentityOAuth2Exception {

        String url;
        ObjectMapper mapper;
        url = String.format(CP_BASE_URL + "/t/%s/api/server/v1/applications/%s/inbound-protocols/oidc",
                tenantDomain, applicationId);
        String oidcString = callControlPlane(url);
        mapper = new ObjectMapper();
        try {
            OpenIDConnectConfiguration oidcConfig = mapper.readValue(oidcString, OpenIDConnectConfiguration.class);
            return new ApiModelToOAuthConsumerApp().apply(applicationName, oidcConfig);
        } catch (JsonProcessingException e) {
            throw new IdentityOAuth2Exception("Error while parsing the application model", e);
        }
    }

    private String callControlPlane(String url) throws IdentityOAuth2Exception {

        final HttpHost targetHost = new HttpHost("localhost", 9443, "https");
        final BasicCredentialsProvider provider = new BasicCredentialsProvider();

        provider.setCredentials(
                new AuthScope(targetHost),
                new UsernamePasswordCredentials("user", "password"));

        AuthCache authCache = new BasicAuthCache();
        authCache.put(targetHost, new BasicScheme());

        HttpClientContext localContext = HttpClientContext.create();
        localContext.setAuthCache(authCache);

//        AuthScope authScope = new AuthScope(targetHost);
//        provider.setCredentials(authScope, new UsernamePasswordCredentials("admin", "admin"));

//        try (CloseableHttpClient httpClient = HttpClientBuilder.create()
//                .setDefaultCredentialsProvider(provider).build()) {
        try (CloseableHttpClient httpClient = HttpClientBuilder.create().build()) {

            HttpGet request = new HttpGet(url);
            final byte[] encodedAuth = Base64.encodeBase64("admin:admin".getBytes(StandardCharsets.UTF_8));
            final String authHeader = "Basic " + new String(encodedAuth, StandardCharsets.UTF_8);
            request.setHeader(HttpHeaders.AUTHORIZATION, authHeader);

            try (CloseableHttpResponse response = httpClient.execute(request)) {

                // Get HttpResponse Status
                LOG.info(response.getProtocolVersion());              // HTTP/1.1
                LOG.info(response.getStatusLine().getStatusCode());   // 200
                LOG.info(response.getStatusLine().getReasonPhrase()); // OK
                LOG.info(response.getStatusLine().toString());        // HTTP/1.1 200 OK

                HttpEntity entity = response.getEntity();
                if (entity != null) {
                    // return it as a String
                    String result = EntityUtils.toString(entity);
                    return result;
                }
            }
        } catch (IOException e) {
            throw new IdentityOAuth2Exception("Error while invoking the control plane.", e);
        }

        throw new IdentityOAuth2Exception("No data found.");
    }

    @Override
    public OAuthAppDO getAppInformationByAppName(String appName)
            throws InvalidOAuthClientException, IdentityOAuth2Exception {

        return null;
    }

    @Override
    public void updateConsumerApplication(OAuthAppDO oauthAppDO) throws IdentityOAuthAdminException {

    }

    @Override
    public void removeConsumerApplication(String consumerKey) throws IdentityOAuthAdminException {

    }

    @Override
    public void removeConsumerApplicationsByTenantId(int tenantId) throws IdentityOAuthAdminException {

    }

    @Override
    public void updateOAuthConsumerApp(String appName, String consumerKey)
            throws IdentityApplicationManagementException {

    }

    @Override
    public void updateOAuthConsumerApp(ServiceProvider serviceProvider, String consumerKey)
            throws IdentityApplicationManagementException, IdentityOAuthAdminException {

    }

    @Override
    public String getConsumerAppState(String consumerKey) throws IdentityOAuthAdminException {

        return null;
    }

    @Override
    public void updateConsumerAppState(String consumerKey, String state) throws IdentityApplicationManagementException {

    }

    @Override
    public boolean isDuplicateApplication(String username, int tenantId, String userDomain, OAuthAppDO consumerAppDTO)
            throws IdentityOAuthAdminException {

        return false;
    }

    @Override
    public boolean isDuplicateConsumer(String consumerKey) throws IdentityOAuthAdminException {

        return false;
    }

    @Override
    public List<String> getOIDCAudiences(String tenantDomain, String consumerKey) throws IdentityOAuth2Exception {

        return null;
    }

    @Override
    public void removeOIDCProperties(String tenantDomain, String consumerKey) throws IdentityOAuthAdminException {

    }
}
