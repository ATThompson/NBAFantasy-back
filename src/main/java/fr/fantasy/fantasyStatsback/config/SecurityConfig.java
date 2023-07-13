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

@EnableWebSecurity
@Configuration
public class SecurityConfig {


    @Autowired
    OAuth2AuthorizedClientService authorizedClientService;

    private final TokenFilter tokenFilter;

    private final ObjectMapper mapper;
    @Autowired
    private OAuthController oauthController;

    @Autowired
    private CustomStatelessAuthorizationRequestRepository customStatelessAuthorizationRequestRepository;


    public SecurityConfig(TokenFilter tokenFilter, ObjectMapper mapper) {
        this.tokenFilter = tokenFilter;
        this.mapper = mapper;
    }

        @Bean
        public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
            http
                    .csrf(csrf -> csrf.disable())
                    .cors(Customizer.withDefaults())
                  /**  .authorizeHttpRequests(authorize ->
                            authorize.requestMatchers("/oauth2/**", "/login**").permitAll()
                                    .anyRequest().authenticated()
                    )*/
                   // Disable "JSESSIONID" cookies
                    .sessionManagement(config -> {
                        config.sessionCreationPolicy(SessionCreationPolicy.STATELESS);
                    })
                    // Endpoint protection
                    .authorizeHttpRequests(config -> {
                        config.anyRequest().permitAll();
                    })
                    .oauth2Login(o2 ->
                            o2.authorizationEndpoint(endpoint ->
                                    endpoint.baseUri(OAuthController.AUTHORIZATION_BASE_URL)
                                    // endpoint.authorizationRequestRepository(new InMemoryRequestRepository())
                                    .authorizationRequestRepository(this.customStatelessAuthorizationRequestRepository)

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
            http.addFilterBefore( tokenFilter, UsernamePasswordAuthenticationFilter.class );
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
            config.setAllowedOrigins( Collections.singletonList( "https://fantasystats.azurewebsites.net" ) );
            config.setAllowedHeaders( Collections.singletonList( "*" ) );
            config.setAllowCredentials(true);

            UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
            source.registerCorsConfiguration( "/**", config );
            return source;
        }

        private void successHandler(HttpServletRequest request,
                                    HttpServletResponse response, Authentication authentication ) throws IOException {
            System.out.println("Hello");
            //String token = tokenStore.generateToken( authentication );
            OAuth2AuthenticationToken authTokenokey = ((OAuth2AuthenticationToken) authentication);
            OAuth2AuthorizedClient authClient = this.authorizedClientService.loadAuthorizedClient(authTokenokey.getAuthorizedClientRegistrationId(), authTokenokey.getName());

            response.getWriter().write(
                    mapper.writeValueAsString( Collections.singletonMap( "accessToken",authClient.getAccessToken().getTokenValue() ) )
            );
        }

    private void authenticationEntryPoint( HttpServletRequest request, HttpServletResponse response,
                                           AuthenticationException authException ) throws IOException {
        response.setStatus( HttpServletResponse.SC_UNAUTHORIZED );
        response.getWriter().write( mapper.writeValueAsString( Collections.singletonMap( "error", "Unauthenticated" ) ) );
    }
    }

