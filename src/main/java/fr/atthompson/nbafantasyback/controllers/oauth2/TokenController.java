package fr.atthompson.nbafantasyback.controllers.oauth2;

import fr.atthompson.nbafantasyback.services.oauth2.RefreshTokenService;
import lombok.AllArgsConstructor;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping(value = "/token")
@RequiredArgsConstructor
public class TokenController {
    private final RefreshTokenService refreshTokenService;

    private Integer chiffre=0;

    @PostMapping(value = "/refresh")
    public String refreshAccessToken(@RequestBody String refreshToken)
    {
        return refreshTokenService.getAccessTokenRefreshed(refreshToken);
    }

    @GetMapping(value = "/ajouter")
    public Integer ajouter(){
        chiffre++;
        return chiffre;
    }
}