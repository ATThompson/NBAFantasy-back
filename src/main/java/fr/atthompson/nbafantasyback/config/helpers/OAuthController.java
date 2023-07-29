package fr.atthompson.nbafantasyback.config.helpers;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.stereotype.Controller;


import java.io.IOException;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.HashMap;

@Controller
public class OAuthController {

    @Autowired
    OAuth2AuthorizedClientService authorizedClientService;

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
