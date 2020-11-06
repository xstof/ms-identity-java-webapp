// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package com.microsoft.azure.msalwebsample;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URLEncoder;
import java.text.ParseException;
import java.util.*;
import java.util.concurrent.*;

import javax.naming.ServiceUnavailableException;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import com.microsoft.aad.msal4j.*;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.openid.connect.sdk.AuthenticationErrorResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationResponseParser;
import com.nimbusds.openid.connect.sdk.AuthenticationSuccessResponse;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
public class AuthFilter implements Filter {

    private static final String STATE = "state";
    private static final String FAILED_TO_VALIDATE_MESSAGE = "Failed to validate data received from Authorization service - ";

    private List<String> excludedUrls = Arrays.asList("/", "/msal4jsample/");

    Logger logger = LoggerFactory.getLogger("Authfilter");

    @Autowired
    AuthHelper authHelper;

    @Override
    public void doFilter(ServletRequest request, ServletResponse response,
                         FilterChain chain) throws IOException, ServletException {
        if (request instanceof HttpServletRequest) {
            logger.info("entered auth middleware");
            HttpServletRequest httpRequest = (HttpServletRequest) request;
            HttpServletResponse httpResponse = (HttpServletResponse) response;
            try {
                String currentUri = httpRequest.getRequestURL().toString();
                String path = httpRequest.getServletPath();
                String queryStr = httpRequest.getQueryString();
                String fullUrl = currentUri + (queryStr != null ? "?" + queryStr : "");

                // exclude home page
                if(excludedUrls.contains(path)){
                    logger.info("auth middleware: url is excluded");
                    chain.doFilter(request, response);
                    return;
                }
                // check if user has a AuthData in the session
                if (!AuthHelper.isAuthenticated(httpRequest)) {
                    logger.info("auth middleware: http request is not authenticated");
                    if(AuthHelper.containsAuthenticationCode(httpRequest)){
                        logger.info("auth middleware: found authcode");
                        // response should have authentication code, which will be used to acquire access token
                        processAuthenticationCodeRedirect(httpRequest, currentUri, fullUrl);

                        CookieHelper.removeStateNonceCookies(httpResponse);
                    } else {
                        // not authenticated, redirecting to login.microsoft.com so user can authenticate
                        logger.info("auth middleware: redirecting towards Sign-Up Sign-In B2C policy");
                        logger.info("auth middleware: authHelper.configuration.signUpSignInAuthority is {}", authHelper.configuration.signUpSignInAuthority);
                        sendAuthRedirect(authHelper.configuration.signUpSignInAuthority, httpRequest, httpResponse);
                        return;
                    }
                }
                if (isAccessTokenExpired(httpRequest)) {
                    authHelper.updateAuthDataUsingSilentFlow(httpRequest);
                }
            } catch (MsalException authException) {
                // something went wrong (like expiration or revocation of token)
                // we should invalidate AuthData stored in session and redirect to Authorization server
                authHelper.removePrincipalFromSession(httpRequest);
                sendAuthRedirect(authHelper.configuration.signUpSignInAuthority, httpRequest, httpResponse);
                return;
            } catch (Throwable exc) {
                httpResponse.setStatus(500);
                request.setAttribute("error", exc.getMessage());
                request.getRequestDispatcher("/error").forward(request, response);
                return;
            }
        }
        chain.doFilter(request, response);
    }

    private boolean isAccessTokenExpired(HttpServletRequest httpRequest) {
        IAuthenticationResult result = AuthHelper.getAuthSessionObject(httpRequest);
        return result.expiresOnDate().before(new Date());
    }

    private void processAuthenticationCodeRedirect(HttpServletRequest httpRequest, String currentUri, String fullUrl)
            throws Throwable {

        Map<String, List<String>> params = new HashMap<>();
        for (String key : httpRequest.getParameterMap().keySet()) {
            params.put(key, Collections.singletonList(httpRequest.getParameterMap().get(key)[0]));
        }
        // validate that state in response equals to state in request
        validateState(CookieHelper.getCookie(httpRequest, CookieHelper.MSAL_WEB_APP_STATE_COOKIE), params.get(STATE).get(0));

        AuthenticationResponse authResponse = AuthenticationResponseParser.parse(new URI(fullUrl), params);
        if (AuthHelper.isAuthenticationSuccessful(authResponse)) {
            AuthenticationSuccessResponse oidcResponse = (AuthenticationSuccessResponse) authResponse;
            // validate that OIDC Auth Response matches Code Flow (contains only requested artifacts)
            validateAuthRespMatchesAuthCodeFlow(oidcResponse);

            logger.info("auth middleware: getting auth result by auth code");
            IAuthenticationResult result = authHelper.getAuthResultByAuthCode(
                    httpRequest,
                    oidcResponse.getAuthorizationCode(),
                    currentUri,
                    Collections.singleton(authHelper.configuration.apiScope));

            // validate nonce to prevent reply attacks (code maybe substituted to one with broader access)
            validateNonce(CookieHelper.getCookie(httpRequest, CookieHelper.MSAL_WEB_APP_NONCE_COOKIE),
                    getNonceClaimValueFromIdToken(result.idToken()));
            logger.info("auth middleware: nonce validated");

            authHelper.setSessionPrincipal(httpRequest, result);
        } else {
            AuthenticationErrorResponse oidcResponse = (AuthenticationErrorResponse) authResponse;
            throw new Exception(String.format("Request for auth code failed: %s - %s",
                    oidcResponse.getErrorObject().getCode(),
                    oidcResponse.getErrorObject().getDescription()));
        }
    }

    void sendAuthRedirect(String authoriy, HttpServletRequest httpRequest, HttpServletResponse httpResponse) throws IOException {
        // state parameter to validate response from Authorization server and nonce parameter to validate idToken
        String state = UUID.randomUUID().toString();
        String nonce = UUID.randomUUID().toString();

        logger.info("auth middleware: set state nonce cookie");
        CookieHelper.setStateNonceCookies(httpRequest, httpResponse, state, nonce);

        logger.info("auth middleware: set 302 response status");
        httpResponse.setStatus(302);
        
        String redirectUrl = getRedirectUrl(authoriy, httpRequest.getParameter("claims"), state, nonce);
        logger.info("auth middleware: redirecting to {}", redirectUrl);
        httpResponse.sendRedirect(redirectUrl);
    }

    private String getNonceClaimValueFromIdToken(String idToken) throws ParseException {
        return (String) JWTParser.parse(idToken).getJWTClaimsSet().getClaim("nonce");
    }

    private void validateState(String cookieValue, String state) throws Exception {
        if (StringUtils.isEmpty(state) || !state.equals(cookieValue)) {
            throw new Exception(FAILED_TO_VALIDATE_MESSAGE + "could not validate state");
        }
    }

    private void validateNonce(String cookieValue, String nonce) throws Exception {
        if (StringUtils.isEmpty(nonce) || !nonce.equals(cookieValue)) {
            throw new Exception(FAILED_TO_VALIDATE_MESSAGE + "could not validate nonce");
        }
    }

    private void validateAuthRespMatchesAuthCodeFlow(AuthenticationSuccessResponse oidcResponse) throws Exception {
        if (oidcResponse.getIDToken() != null || oidcResponse.getAccessToken() != null ||
                oidcResponse.getAuthorizationCode() == null) {
            throw new Exception(FAILED_TO_VALIDATE_MESSAGE + "unexpected set of artifacts received");
        }
    }

    private String getRedirectUrl(String authority, String claims, String state, String nonce)
            throws UnsupportedEncodingException {

        logger.info("auth middleware: getting redirect url for authority: {}", authority);
        String redirectUrl = authority.replace("/tfp", "") + "oauth2/v2.0/authorize?" +
                "response_type=code&" +
                "response_mode=query&" +
                "redirect_uri=" + URLEncoder.encode(authHelper.configuration.redirectUri, "UTF-8") +
                "&client_id=" + authHelper.configuration.clientId +
                "&scope=" + URLEncoder.encode("openid offline_access profile " +
                authHelper.configuration.apiScope, "UTF-8") +
                (StringUtils.isEmpty(claims) ? "" : "&claims=" + claims) +
                "&prompt=select_account" +
                "&state=" + state
                + "&nonce=" + nonce;

        return redirectUrl;
    }
}
