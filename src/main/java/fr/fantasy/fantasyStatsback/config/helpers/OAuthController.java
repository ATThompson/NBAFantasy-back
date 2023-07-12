package fr.fantasy.fantasyStatsback.config.helpers;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestRedirectFilter;
import org.springframework.security.oauth2.client.web.OAuth2LoginAuthenticationFilter;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.stereotype.Controller;


import java.io.IOException;
import java.time.Duration;
import java.util.UUID;

@Controller
public class OAuthController {

    @Autowired
    OAuth2AuthorizedClientService authorizedClientService;
    /**
     * Default = {@value OAuth2AuthorizationRequestRedirectFilter#DEFAULT_AUTHORIZATION_REQUEST_BASE_URI}
     * <p>
     * For instance:
     * - /oauth2/authorization/auth0
     * - /oauth2/authorization/facebook
     * - /oauth2/authorization/google
     */
    public static final String AUTHORIZATION_BASE_URL = "/oauth2/authorization";

    /**
     * Default = {@value OAuth2LoginAuthenticationFilter#DEFAULT_FILTER_PROCESSES_URI}
     * <p>
     * For instance:
     * - /oauth2/callback/auth0
     * - /oauth2/callback/facebook
     * - /oauth2/callback/google
     */
    public static final String CALLBACK_BASE_URL = "/oauth2/callback";

    public static final String OAUTH_COOKIE_NAME = "OAUTH";
    public static final String SESSION_COOKIE_NAME = "SESSION";



    public void oauthRedirectResponse(HttpServletRequest request, HttpServletResponse response, String url) throws IOException {
        response.setStatus(HttpServletResponse.SC_OK);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.getWriter().write("{ \"redirectUrl\": \"%s\" }".formatted(url));
    }


    public void oauthSuccessCallback(OAuth2AuthorizedClient client, Authentication authentication) {
        System.out.println("CallBack succes");
    }

    public void oauthSuccessResponse(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException {
        //String accountId = AuthenticationHelper.retrieveAccountId(authentication);
        OAuth2AuthenticationToken authTokenokey = ((OAuth2AuthenticationToken) authentication);
        OAuth2AuthorizedClient authClient = this.authorizedClientService.loadAuthorizedClient(authTokenokey.getAuthorizedClientRegistrationId(), authTokenokey.getName());

        //response.addHeader(HttpHeaders.SET_COOKIE, CookieHelper.generateExpiredCookie(OAUTH_COOKIE_NAME,request));
        response.addHeader(HttpHeaders.SET_COOKIE, CookieHelper.generateCookie(SESSION_COOKIE_NAME, authClient.getAccessToken().getTokenValue(), Duration.ofDays(1),request));
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.getWriter().write("{ \"status\": \"success\" }");
    }


    public void oauthFailureResponse(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException {
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setHeader(HttpHeaders.SET_COOKIE, CookieHelper.generateExpiredCookie(OAUTH_COOKIE_NAME,request));
        response.getWriter().write("{ \"status\": \"failure\" }");
    }

}
