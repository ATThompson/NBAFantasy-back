package fr.atthompson.nbafantasyback.services.oauth2;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.util.Map;

@Service
@RequiredArgsConstructor
public class RefreshTokenService {
    @Value("${spring.security.oauth2.client.registration.yahoo.client-id}")
    private String client_id;
    @Value("${spring.security.oauth2.client.registration.yahoo.client-secret}")
    private String client_secret;
    private String grant_type = "refresh_token";
    private String redirect_uri = "oob";
    @Value("${spring.security.oauth2.client.provider.yahoo.token-uri}")
    private String get_token_uri;


    public String getAccessTokenRefreshed(String refreshToken){
        var restTemplate = new RestTemplate();
        var headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        // Generate Multimap to pass parameters in request body
        MultiValueMap<String, String> map = new LinkedMultiValueMap<>();
        map.add("client_id", client_id);
        map.add("client_secret", client_secret);
        map.add("redirect_uri", redirect_uri);
        map.add("grant_type", grant_type);
        map.add("refresh_token", refreshToken);

        var request = new HttpEntity<MultiValueMap<String, String>>(map, headers);
        var response = restTemplate.postForEntity(get_token_uri, request, Map.class);
        return (String) response.getBody().get("access_token");
    }
}
