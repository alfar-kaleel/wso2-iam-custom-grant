/*
 * Copyright (c) 2015, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.sample.identity.oauth2.grant.password;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.common.exception.OAuthProblemException;
import org.wso2.carbon.context.CarbonContext;
import org.wso2.carbon.identity.application.common.model.*;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationManagementUtil;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.ResponseHeader;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenRespDTO;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.handlers.grant.PasswordGrantHandler;
import org.wso2.carbon.idp.mgt.IdentityProviderManagementException;
import org.wso2.carbon.idp.mgt.IdentityProviderManager;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import javax.mail.AuthenticationFailedException;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.util.Map;
import java.util.Properties;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

/**
 * Modified version of password grant type to modify the access token.
 */
public class ModifiedAccessTokenPasswordGrant extends PasswordGrantHandler {

    private static Log log = LogFactory.getLog(ModifiedAccessTokenPasswordGrant.class);

    String ACCOUNT_DISABLED_CLAIM="http://wso2.org/claims/identity/accountDisabled";
    String ACCOUNT_LOCKED_CLAIM="http://wso2.org/claims/identity/accountLocked";
    String ACCOUNT_LOCKED_REASON="http://wso2.org/claims/identity/lockedReason";
    String ACCOUNT_AUTO_UNLOCKED_TIME="http://wso2.org/claims/identity/unlockTimeInMinutes";
    String ACCOUNT_FAILED_LOGIN_ATTEMPT="http://wso2.org/claims/identity/failedLoginAttempts";
    String ACCOUNT_LOCKED_REASON_MAX_ATTEMPTS_EXCEEDED="MAX_ATTEMPTS_EXCEEDED";
    String ACCOUNT_LOCKED_REASON_ADMIN_INITIATED="ADMIN_INITIATED";
    String ACCOUNT_ALLOWED_MAXIMUM_FAILED_COUNT="account.lock.handler.On.Failure.Max.Attempts";
    Properties prop = new Properties();
    ClassLoader loader = Thread.currentThread().getContextClassLoader();
    FileReader reader = new FileReader("repository/conf/password-expiry.properties");

    public ModifiedAccessTokenPasswordGrant() throws FileNotFoundException {
    }

    @Override
    public OAuth2AccessTokenRespDTO issue(OAuthTokenReqMessageContext tokReqMsgCtx) throws IdentityOAuth2Exception {

        Boolean passwordExpiry,jwtTokenEnabled;
        String userStores = null;
        String[] userStoresArr = null;
        String currentUserStore = tokReqMsgCtx.getAuthorizedUser().getUserStoreDomain();
        OAuth2AccessTokenRespDTO tokenRespDTO =  super.issue(tokReqMsgCtx);
        System.out.println("Checking that the new build has created");

        try {
            prop.load(reader);
            passwordExpiry = (Boolean) Boolean.parseBoolean(prop.getProperty("password.expiry"));
            jwtTokenEnabled = (Boolean) Boolean.parseBoolean(prop.getProperty("token.issuer.jwt.enabled"));
            userStores = prop.getProperty("user.store.list");
            userStoresArr = userStores.split(",");


        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        log.info("Retrived passwordExpiry is : " + passwordExpiry);
        log.info("Retrived jwtTokenEnabled is : " + jwtTokenEnabled);
        log.info("Retrieved Userstores are : " + userStores);
        log.info("Current user store is : " + currentUserStore);
        log.info("Converted userStoresArr length is : " + userStoresArr.length);
        if(!jwtTokenEnabled){
            log.info("Jwt Token is disabled");
            tokenRespDTO.setAccessToken(generateDefaultToken());
        }
        try {
            for (String userStore : userStoresArr) {
                if (currentUserStore.equalsIgnoreCase(userStore) && passwordExpiry) {
                    log.info("Password Expiry is enabled");
                    validatePassword(tokReqMsgCtx);
                }
            }
           if(tokReqMsgCtx.getProperty("RESPONSE_HEADERS") != null){
               ResponseHeader[] rspHeader = (ResponseHeader[]) tokReqMsgCtx.getProperty("RESPONSE_HEADERS");
               String rspValue =  rspHeader[0].getValue();
               log.info("Resp Value is : " + rspValue);
               tokenRespDTO.setError(true);
               tokenRespDTO.setErrorCode(rspValue);

               switch (rspValue){
                   case "password_expired":
                       tokenRespDTO.setErrorMsg("Your password has expired, Please reset the password via the web");
                        break;
                   case "field_missing" :
                       tokenRespDTO.setErrorMsg("PasswordExpiredAt Field is missing");
                       break;
               }
           }
        } catch (OAuthProblemException e) {
            log.error(e);
        } catch (AuthenticationFailedException e) {
           log.error(e.getMessage());
        }
        return tokenRespDTO;
    }

    private String generateDefaultToken(){
        String token = UUID.randomUUID().toString();
        return token;
    }
    /**
     * Demo sample for generating custom access token
     *
     * @param userName
     * @return
     */
    private void validatePassword(OAuthTokenReqMessageContext oAuthTokenMsgCtx) throws OAuthProblemException, AuthenticationFailedException {
        OAuth2AccessTokenReqDTO tokenReq = oAuthTokenMsgCtx.getOauth2AccessTokenReqDTO();
        String userName = null;
        String tenantDomain = oAuthTokenMsgCtx.getAuthorizedUser().getTenantDomain();
        String userStore = oAuthTokenMsgCtx.getAuthorizedUser().getUserStoreDomain();
        userName= MultitenantUtils.getTenantAwareUsername(tokenReq.getResourceOwnerUsername());
        String pwdChangedAt = "";
        Map<String, String> claimValues = null;
        long pwdExpiredTime = System.currentTimeMillis() + TimeUnit.DAYS.toMillis(1);
        IdentityProvider idp;
        ResponseHeader responseHeader = new ResponseHeader();
        try {
            idp =  IdentityProviderManager.getInstance().getResidentIdP(tenantDomain);
        } catch (IdentityProviderManagementException e) {
            throw new AuthenticationFailedException("Error occurred while retrieving the resident IdP for tenant : " + tenantDomain);
        }

        try {
            claimValues = CarbonContext.getThreadLocalCarbonContext().getUserRealm().getUserStoreManager()
                    .getUserClaimValues(userName, new String[]{"http://wso2.org/claims/identity/lastPasswordUpdateTime"}, null);
            pwdChangedAt = claimValues.get("http://wso2.org/claims/identity/lastPasswordUpdateTime");
        } catch (UserStoreException e) {
            log.error(e);
        }
        log.info("Current User is : " + userName);
        log.info("USerStore is : " + userStore);
        log.info("Retrieved pwdChangedAt is : "+ pwdChangedAt );
        IdentityProviderProperty retrievedpasswordExpiryInDays = IdentityApplicationManagementUtil
                .getProperty(idp.getIdpProperties(), "passwordExpiry.passwordExpiryInDays");
        String pwdExpiryInDays = null;
        if (retrievedpasswordExpiryInDays != null) {
            pwdExpiryInDays = retrievedpasswordExpiryInDays.getValue();
        }else{
            log.info("PasswordExpiryInDays field is missing in the console");
        }

        log.info("Retrieved passwordExpiryInDays : " + pwdExpiryInDays);
        if(pwdChangedAt != null) {
            long duration = TimeUnit.DAYS.toMillis(Integer.parseInt(pwdExpiryInDays));
            pwdExpiredTime = Long.parseLong(pwdChangedAt) + duration;
            log.info("Current Time in mills  : " + System.currentTimeMillis());
            log.info("Pwd Expired time : " + pwdExpiredTime);
        }else{
            responseHeader.setKey("SampleHeader-998");
            responseHeader.setValue("field_missing");
            oAuthTokenMsgCtx.addProperty("RESPONSE_HEADERS", new ResponseHeader[]{responseHeader});
        }

        if(System.currentTimeMillis() > pwdExpiredTime){
            log.info("Hit the condition");
            responseHeader.setKey("SampleHeader-999");
            responseHeader.setValue("password_expired");
            oAuthTokenMsgCtx.addProperty("RESPONSE_HEADERS", new ResponseHeader[]{responseHeader});
        }else{
            log.info("P/W Not expired");
        }
    }

    @Override
    public boolean validateGrant(OAuthTokenReqMessageContext tokReqMsgCtx) throws IdentityOAuth2Exception {
        OAuth2AccessTokenReqDTO tokenReq = tokReqMsgCtx.getOauth2AccessTokenReqDTO();
        String userName=null;
        try {
            return super.validateGrant(tokReqMsgCtx);
        } catch (IdentityOAuth2Exception e) {
            Map<String, String> claim_values = null;
            userName= MultitenantUtils.getTenantAwareUsername(tokenReq.getResourceOwnerUsername());
            try {
                claim_values = CarbonContext.getThreadLocalCarbonContext().getUserRealm().getUserStoreManager()
                        .getUserClaimValues(userName, new String[]{ACCOUNT_DISABLED_CLAIM,ACCOUNT_LOCKED_CLAIM,ACCOUNT_LOCKED_REASON,ACCOUNT_AUTO_UNLOCKED_TIME,ACCOUNT_FAILED_LOGIN_ATTEMPT}, null);
            } catch (UserStoreException userStoreException) {
                log.error("An error has been occurred: "+userStoreException.getMessage());
                throw new IdentityOAuth2Exception("LOGIN FAILED! PLEASE RECHECK THE USERNAME AND PASSWORD AND TRY AGAIN.");
            }
            String accountLocked = claim_values.get(ACCOUNT_LOCKED_CLAIM);
            boolean accountLockedClaim=Boolean.parseBoolean((null==accountLocked)?"false":accountLocked.trim());

            String accountDisabled = claim_values.get(ACCOUNT_DISABLED_CLAIM);
            boolean accountDisabledClaim=Boolean.parseBoolean((null==accountDisabled)?"false":accountDisabled.trim());

            if(accountLockedClaim){
                String accountLockedReason = claim_values.get(ACCOUNT_LOCKED_REASON);
                if(null==accountLockedReason){
                    //throw new IdentityOAuth2Exception("SOMETHING WENT WRONG WITH LOGIN. PLEASE TRY AFTER SOMETIME OR PLEASE CONTACT CALL CENTRE FOR FURTHER ASSISTANCE");
                    String accountFailedLoginattempts = claim_values.get(ACCOUNT_FAILED_LOGIN_ATTEMPT);
                    int accountFailedLoginattemptsClaim=(null==accountFailedLoginattempts)?0:Integer.parseInt(accountFailedLoginattempts.trim());
                    throw new IdentityOAuth2Exception("LOGIN FAILED! PLEASE RECHECK THE USERNAME AND PASSWORD AND TRY AGAIN. REMAINING LOGIN ATTEMPTS: "+(5-accountFailedLoginattemptsClaim));
                }else if(ACCOUNT_LOCKED_REASON_MAX_ATTEMPTS_EXCEEDED.equals(accountLockedReason.trim())){
                    String accountUnlockedTime = claim_values.get(ACCOUNT_AUTO_UNLOCKED_TIME);
                    int unlockTimeInMinutes=(null==accountUnlockedTime)?(0):Integer.parseInt(accountUnlockedTime.trim());
                    throw new IdentityOAuth2Exception("YOUR ACCOUNT IS LOCKED. PLEASE TRY AGAIN IN "+unlockTimeInMinutes+" MINUTE(S).");
                }else if(ACCOUNT_LOCKED_REASON_ADMIN_INITIATED.equals(accountLockedReason.trim())){
                    throw new IdentityOAuth2Exception("YOUR ACCOUNT IS LOCKED. PLEASE CONTACT CUSTOMER CARE CENTER FOR FURTHER ASSISTANCE.");
                }else{
                    throw new IdentityOAuth2Exception("YOUR ACCOUNT HAS AN UNVERIFIED STATUS. PLEASE CONTACT CUSTOMER CARE CENTRE FOR FURTHER ASSISTANCE.");
                }
            }else if(accountDisabledClaim){
                throw new IdentityOAuth2Exception("YOUR ACCOUNT IS DISABLED. PLEASE CONTACT CUSTOMER CARE CENTER FOR FURTHER ASSISTANCE");
            }else{
                String accountFailedLoginattempts = claim_values.get(ACCOUNT_FAILED_LOGIN_ATTEMPT);
                int accountFailedLoginattemptsClaim=(null==accountFailedLoginattempts)?0:Integer.parseInt(accountFailedLoginattempts.trim());
                throw new IdentityOAuth2Exception("LOGIN FAILED! PLEASE RECHECK THE USERNAME AND PASSWORD AND TRY AGAIN. REMAINING LOGIN ATTEMPTS: "+(5-accountFailedLoginattemptsClaim));
            }
        }
    }
}