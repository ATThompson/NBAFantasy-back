package fr.atthompson.nbafantasyback.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.io.IOException;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;

@EnableWebSecurity
@Configuration
@RequiredArgsConstructor
public class SecurityConfig {

    private final OAuth2AuthorizedClientService authorizedClientService;
    private final ObjectMapper mapper;

    @Value("${allowed.origins}")
    private String allowedOrigins;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf.disable())
                .cors(Customizer.withDefaults())
                .authorizeHttpRequests(config -> {
                    config.anyRequest().permitAll();
                })
                .oauth2Login(o2 ->
                        o2.authorizationEndpoint(endpoint ->
                                        endpoint.authorizationRequestRepository(new InMemoryRequestRepository())
                                )
                                .successHandler(this::oauthSuccessResponse)
                                .failureHandler(this::oauthFailureResponse)
                )
                .exceptionHandling(exception ->
                        exception.authenticationEntryPoint(this::authenticationEntryPoint))
                .logout(logout -> logout.addLogoutHandler(this::logout).logoutSuccessHandler(this::onLogoutSuccess));
        ;
        return http.build();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedMethods(Arrays.asList("GET", "PUT", "POST", "DELETE"));
        config.setAllowedOrigins(Collections.singletonList(allowedOrigins));
        config.setAllowedHeaders(Collections.singletonList("*"));
        config.setAllowCredentials(true);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }

    private void authenticationEntryPoint(HttpServletRequest request, HttpServletResponse response,
                                          AuthenticationException authException) throws IOException {
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.getWriter().write(mapper.writeValueAsString(Collections.singletonMap("error", "Unauthenticated")));
    }

    private void oauthSuccessResponse(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException {
        OAuth2AuthenticationToken authToken = ((OAuth2AuthenticationToken) authentication);
        OAuth2AuthorizedClient authClient = this.authorizedClientService.loadAuthorizedClient(authToken.getAuthorizedClientRegistrationId(), authToken.getName());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);

        var mapResponse = new HashMap<String, String>();
        mapResponse.put("accessToken", authClient.getAccessToken().getTokenValue());
        mapResponse.put("expiredAt", ZonedDateTime.ofInstant(authClient.getAccessToken().getExpiresAt(), ZoneId.of("Europe/Paris")).toString());
        mapResponse.put("refreshToken", authClient.getRefreshToken().getTokenValue());
        mapResponse.put("name", authClient.getPrincipalName());
        response.getWriter().write(
                mapper.writeValueAsString(mapResponse)
        );
    }

    private void oauthFailureResponse(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException {
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.getWriter().write("{ \"error\": \"unauthenticated\" }");
    }

    private void logout(HttpServletRequest request, HttpServletResponse response,
                        Authentication authentication) {
        // You can process token here
        System.out.println("Auth token is - " + request.getHeader("Authorization"));
    }

    private void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response,
                         Authentication authentication) throws IOException, ServletException {
        // this code is just sending the 200 ok response and preventing redirect
        response.setStatus(HttpServletResponse.SC_OK);
    }
}

