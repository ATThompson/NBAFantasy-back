package fr.fantasy.fantasyStatsback.config;

import fr.fantasy.fantasyStatsback.config.helpers.OAuthController;
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestRedirectFilter;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.stereotype.Component;

import java.lang.reflect.Field;

public class CustomAuthorizationRedirectFilter {

    /**public CustomAuthorizationRedirectFilter(
            OAuthController oAuthController,
            OAuth2AuthorizationRequestResolver authorizationRequestResolver,
            AuthorizationRequestRepository<OAuth2AuthorizationRequest> authorizationRequestRepository
    ) throws NoSuchFieldException, IllegalAccessException {
        super(authorizationRequestResolver);
        super.setAuthorizationRequestRepository(authorizationRequestRepository);
        // Reflection hack to overwrite the parent's redirect strategy
        RedirectStrategy customStrategy = oAuthController::oauthRedirectResponse;
        Field field = OAuth2AuthorizationRequestRedirectFilter.class.getDeclaredField("authorizationRedirectStrategy");
        field.setAccessible(true);
        field.set(this, customStrategy);
    }*/

}
