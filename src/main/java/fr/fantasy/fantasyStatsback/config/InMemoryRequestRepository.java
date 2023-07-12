package fr.fantasy.fantasyStatsback.config;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;

import java.util.HashMap;
import java.util.Map;

public class InMemoryRequestRepository implements AuthorizationRequestRepository< OAuth2AuthorizationRequest > {

    private final Map< String, OAuth2AuthorizationRequest > cache = new HashMap<>();

    @Override
    public OAuth2AuthorizationRequest loadAuthorizationRequest( HttpServletRequest request ) {
        System.out.println("LoadAutorisatioRequest");
        String state = request.getParameter( "state" );
        if ( state != null ) {
            return removeAuthorizationRequest( request,null );
        }
        return null;
    }

    @Override
    public void saveAuthorizationRequest( OAuth2AuthorizationRequest authorizationRequest,
                                          HttpServletRequest request, HttpServletResponse response ) {
        System.out.println("Save");
        String state = authorizationRequest.getState();
        cache.put( state, authorizationRequest );
    }

    @Override
    public OAuth2AuthorizationRequest removeAuthorizationRequest( HttpServletRequest request, HttpServletResponse response ) {
        System.out.println("Remove");
        String state = request.getParameter( "state" );
        if ( state != null ) {
            return cache.remove( state );
        }

        return null;
    }
}
