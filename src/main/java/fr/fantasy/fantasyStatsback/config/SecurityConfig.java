package fr.fantasy.fantasyStatsback.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import fr.fantasy.fantasyStatsback.config.helpers.OAuthController;
import jakarta.servlet.Filter;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestRedirectFilter;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;

@EnableWebSecurity
@Configuration
public class SecurityConfig {


    @Autowired
    OAuth2AuthorizedClientService authorizedClientService;


    private final ObjectMapper mapper;
    @Autowired
    private OAuthController oauthController;



    public SecurityConfig( ObjectMapper mapper) {
        this.mapper = mapper;
    }

        @Bean
        public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
            http
                    .csrf(csrf -> csrf.disable())
                    .cors(Customizer.withDefaults())
                    // Endpoint protection
                    .authorizeHttpRequests(config -> {
                        config.anyRequest().permitAll();
                    })
                    .oauth2Login(o2 ->
                            o2.authorizationEndpoint(endpoint ->
                                    //endpoint.baseUri(OAuthController.AUTHORIZATION_BASE_URL)
                                     endpoint.authorizationRequestRepository(new InMemoryRequestRepository())
                                    //.authorizationRequestRepository(this.customStatelessAuthorizationRequestRepository)

                                    )
                                    //.successHandler(this::successHandler)
                                    .successHandler(this.oauthController::oauthSuccessResponse)
                                    .failureHandler(this.oauthController::oauthFailureResponse)
                    )
            /**
                    .oauth2Login(config -> {
                        config.authorizationEndpoint(subconfig -> {
                            subconfig.baseUri(OAuthController.AUTHORIZATION_BASE_URL);
                            //subconfig.authorizationRequestResolver(this.customAuthorizationRequestResolver);
                            subconfig.authorizationRequestRepository(this.customStatelessAuthorizationRequestRepository);
                        });
                        config.successHandler(this.oauthController::oauthSuccessResponse);
                        config.failureHandler(this.oauthController::oauthFailureResponse);
                    })*/
                    .exceptionHandling(exception ->
                            exception.authenticationEntryPoint(this::authenticationEntryPoint))
                    .logout(cust -> cust.addLogoutHandler( this::logout ).logoutSuccessHandler( this::onLogoutSuccess ));;
            //http.addFilterBefore( tokenFilter, UsernamePasswordAuthenticationFilter.class );
            return http.build();
        }
    private void logout(HttpServletRequest request, HttpServletResponse response,
                        Authentication authentication) {
        // You can process token here
        System.out.println("Auth token is - " + request.getHeader( "Authorization" ));
    }

    void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response,
                         Authentication authentication) throws IOException, ServletException {
        // this code is just sending the 200 ok response and preventing redirect
        response.setStatus( HttpServletResponse.SC_OK );
    }
    @Bean
        public CorsConfigurationSource corsConfigurationSource() {
            CorsConfiguration config = new CorsConfiguration();
            config.setAllowedMethods( Arrays.asList("GET","PUT","POST","DELETE" ) );
            config.setAllowedOrigins( Collections.singletonList( "https://localhost:4200" ) );
            //config.setAllowedOrigins( Collections.singletonList( "https://fantasystats.azurewebsites.net" ) );
            config.setAllowedHeaders( Collections.singletonList( "*" ) );
            config.setAllowCredentials(true);

            UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
            source.registerCorsConfiguration( "/**", config );
            return source;
        }
    private void authenticationEntryPoint( HttpServletRequest request, HttpServletResponse response,
                                           AuthenticationException authException ) throws IOException {
        response.setStatus( HttpServletResponse.SC_UNAUTHORIZED );
        response.getWriter().write( mapper.writeValueAsString( Collections.singletonMap( "error", "Unauthenticated" ) ) );
    }
    }

