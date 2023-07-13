package fr.fantasy.fantasyStatsback.config;


import fr.fantasy.fantasyStatsback.config.helpers.CookieHelper;
import fr.fantasy.fantasyStatsback.config.helpers.EncryptionHelper;
import fr.fantasy.fantasyStatsback.config.helpers.OAuthController;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.stereotype.Component;
import org.springframework.util.SerializationUtils;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.time.Duration;
import java.util.Base64;

@Component
public class CustomStatelessAuthorizationRequestRepository implements AuthorizationRequestRepository<OAuth2AuthorizationRequest> {

    private static final Duration OAUTH_COOKIE_EXPIRY = Duration.ofMinutes(5);
    private static final Base64.Encoder B64E = Base64.getEncoder();
    private static final Base64.Decoder B64D = Base64.getDecoder();

    private final SecretKey encryptionKey;

    public CustomStatelessAuthorizationRequestRepository() throws NoSuchAlgorithmException {
        this.encryptionKey = EncryptionHelper.generateKey();
    }

    public CustomStatelessAuthorizationRequestRepository(char[] encryptionPassword) throws InvalidKeySpecException, NoSuchAlgorithmException {
        byte[] salt = {0}; // A static salt is OK for these short lived session cookies
        this.encryptionKey = EncryptionHelper.generateKey(encryptionPassword, salt);
    }

    @Override
    public OAuth2AuthorizationRequest loadAuthorizationRequest(HttpServletRequest request) {
        System.out.println("LoadAutorisatioRequest");
        return this.retrieveCookie(request);
    }

    @Override
    public void saveAuthorizationRequest(OAuth2AuthorizationRequest authorizationRequest, HttpServletRequest request, HttpServletResponse response) {
        System.out.println("Save");
        if (authorizationRequest == null) {
            this.removeCookie(response);
            return;
        }
        try {
            this.attachCookie(response, authorizationRequest);
        } catch (InvalidAlgorithmParameterException e) {
            throw new RuntimeException(e);
        } catch (NoSuchPaddingException e) {
            throw new RuntimeException(e);
        } catch (IllegalBlockSizeException e) {
            throw new RuntimeException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (BadPaddingException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeyException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public OAuth2AuthorizationRequest removeAuthorizationRequest(HttpServletRequest request, HttpServletResponse response) {
        System.out.println("Remove");
        return loadAuthorizationRequest(request);
    }

    private OAuth2AuthorizationRequest retrieveCookie(HttpServletRequest request) {


        String headerAuthorization = request.getHeader("Authorization");
        System.out.println("Autho header "+headerAuthorization);
        System.out.println("State : " + request.getParameter("state"));
        return CookieHelper.retrieve(request.getCookies(), OAuthController.OAUTH_COOKIE_NAME)
                .map(this::decrypt)
                .orElse(null);
    }

    private void attachCookie(HttpServletResponse response, OAuth2AuthorizationRequest value) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        System.out.println("Attach cookie" +this.encrypt(value) );
        String cookie = CookieHelper.generateCookie(OAuthController.OAUTH_COOKIE_NAME, this.encrypt(value), OAUTH_COOKIE_EXPIRY,null);
        response.setHeader(HttpHeaders.SET_COOKIE, cookie);
        response.setHeader(HttpHeaders.AUTHORIZATION,this.encrypt(value));
    }

    private void removeCookie(HttpServletResponse response) {
        String expiredCookie = CookieHelper.generateExpiredCookie(OAuthController.OAUTH_COOKIE_NAME,null);
        response.setHeader(HttpHeaders.SET_COOKIE, expiredCookie);

    }

    private String encrypt(OAuth2AuthorizationRequest authorizationRequest) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        byte[] bytes = SerializationUtils.serialize(authorizationRequest);
        byte[] encryptedBytes = EncryptionHelper.encrypt(this.encryptionKey, bytes);
        return B64E.encodeToString(encryptedBytes);
    }

    private OAuth2AuthorizationRequest decrypt(String encrypted){
        byte[] encryptedBytes = B64D.decode(encrypted);
        byte[] bytes = new byte[0];
        try {
            bytes = EncryptionHelper.decrypt(this.encryptionKey, encryptedBytes);
        } catch (NoSuchPaddingException e) {
            throw new RuntimeException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (InvalidAlgorithmParameterException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeyException e) {
            throw new RuntimeException(e);
        } catch (IllegalBlockSizeException e) {
            throw new RuntimeException(e);
        } catch (BadPaddingException e) {
            throw new RuntimeException(e);
        }
        return (OAuth2AuthorizationRequest) SerializationUtils.deserialize(bytes);
    }

}