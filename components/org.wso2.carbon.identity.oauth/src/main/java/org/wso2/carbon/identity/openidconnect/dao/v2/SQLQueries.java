/*
 * Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.openidconnect.dao.v2;

/**
 * OIDC sql queries
 */
public class SQLQueries {

    private SQLQueries() {

    }

    /**
     * OIDC Request Object related queries
     */
    public static final String STORE_IDN_OIDC_REQ_OBJECT_REFERENCE = "INSERT INTO IDN_OIDC_REQ_OBJECT_REFERENCE_V2 " +
            "(CONSUMER_KEY_ID, SESSION_DATA_KEY) VALUES ((SELECT ID FROM IDN_OAUTH_CONSUMER_APPS WHERE " +
            "CONSUMER_KEY=?),?)";

    public static final String STORE_IDN_OIDC_REQ_OBJECT_CLAIMS = "INSERT INTO IDN_OIDC_REQ_OBJECT_CLAIMS_V2 " +
            "(REQ_OBJECT_ID,CLAIM_ATTRIBUTE, ESSENTIAL, VALUE, IS_USERINFO) VALUES (?, ?, ?, ?, ?)";

    public static final String STORE_IDN_OIDC_REQ_OBJECT_CLAIM_VALUES = "INSERT INTO IDN_OIDC_REQ_OBJ_CLAIM_VALUES_V2" +
            " (REQ_OBJECT_CLAIMS_ID,CLAIM_VALUES) VALUES (?, ?)";

    public static final String UPDATE_REQUEST_OBJECT = "UPDATE IDN_OIDC_REQ_OBJECT_REFERENCE_V2 SET " +
            "CODE_ID=?,TOKEN_ID=? WHERE SESSION_DATA_KEY=?";

    public static final String REFRESH_REQUEST_OBJECT = "UPDATE IDN_OIDC_REQ_OBJECT_REFERENCE_V2 SET " +
            "TOKEN_ID=? WHERE TOKEN_ID=?";

    public static final String DELETE_REQ_OBJECT_TOKEN_FOR_CODE =
            "DELETE FROM IDN_OIDC_REQ_OBJECT_REFERENCE_V2 WHERE TOKEN_ID = ?";

    public static final String UPDATE_REQUEST_OBJECT_TOKEN_FOR_CODE = "UPDATE IDN_OIDC_REQ_OBJECT_REFERENCE_V2 SET " +
            "TOKEN_ID=? WHERE CODE_ID=?";

    public static final String DELETE_REQ_OBJECT_BY_CODE_ID =
            "DELETE FROM IDN_OIDC_REQ_OBJECT_REFERENCE_V2 WHERE CODE_ID = ?";

    public static final String DELETE_REQ_OBJECT_BY_TOKEN_ID =
            "DELETE FROM IDN_OIDC_REQ_OBJECT_REFERENCE_V2 WHERE TOKEN_ID = ?";

    public static final String RETRIEVE_REQUESTED_CLAIMS_BY_TOKEN = "SELECT CLAIM_ATTRIBUTE, ESSENTIAL, VALUE " +
            " FROM IDN_OIDC_REQ_OBJECT_CLAIMS_V2" +
            " LEFT JOIN IDN_OIDC_REQ_OBJECT_REFERENCE_V2" +
            " ON IDN_OIDC_REQ_OBJECT_CLAIMS_V2.REQ_OBJECT_ID = IDN_OIDC_REQ_OBJECT_REFERENCE_V2.ID" +
            " WHERE TOKEN_ID=? AND IS_USERINFO=? ";

    public static final String RETRIEVE_REQUESTED_CLAIMS_BY_SESSION_DATA_KEY = "SELECT CLAIM_ATTRIBUTE, ESSENTIAL," +
            " VALUE FROM IDN_OIDC_REQ_OBJECT_CLAIMS_V2" +
            " LEFT JOIN IDN_OIDC_REQ_OBJECT_REFERENCE_V2" +
            " ON IDN_OIDC_REQ_OBJECT_CLAIMS_V2.REQ_OBJECT_ID = IDN_OIDC_REQ_OBJECT_REFERENCE_V2.ID" +
            " WHERE SESSION_DATA_KEY=? AND IS_USERINFO=?";

    public static final String RETRIEVE_REQUESTED_CLAIMS_ID =
            "SELECT ID, CLAIM_ATTRIBUTE FROM IDN_OIDC_REQ_OBJECT_CLAIMS_V2 WHERE REQ_OBJECT_ID=? ";
}
