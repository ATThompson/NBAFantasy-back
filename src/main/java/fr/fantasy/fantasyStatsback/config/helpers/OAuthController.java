package fr.fantasy.fantasyStatsback.config.helpers;

import com.fasterxml.jackson.databind.ObjectMapper;
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
import org.springframework.stereotype.Controller;
import org.springframework.util.SerializationUtils;


import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;

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


    public static final String OAUTH_COOKIE_NAME = "OAUTH";

    private final ObjectMapper mapper;

    public OAuthController(ObjectMapper mapper) {
        this.mapper = mapper;
    }


    public void oauthSuccessResponse(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException {
        OAuth2AuthenticationToken authToken = ((OAuth2AuthenticationToken) authentication);
        OAuth2AuthorizedClient authClient = this.authorizedClientService.loadAuthorizedClient(authToken.getAuthorizedClientRegistrationId(), authToken.getName());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);

        var mapResponse = new HashMap<String,String>();
        mapResponse.put("accessToken",authClient.getAccessToken().getTokenValue());
        mapResponse.put("expiredAt", ZonedDateTime.ofInstant(authClient.getAccessToken().getExpiresAt(), ZoneId.of("Europe/Paris")).toString());
        mapResponse.put("refreshToken",authClient.getRefreshToken().getTokenValue());
        mapResponse.put("name",authClient.getPrincipalName());
        response.getWriter().write(
                mapper.writeValueAsString( mapResponse )
        );
    }


    public void oauthFailureResponse(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException {
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.getWriter().write("{ \"error\": \"unauthenticated\" }");
    }

}
