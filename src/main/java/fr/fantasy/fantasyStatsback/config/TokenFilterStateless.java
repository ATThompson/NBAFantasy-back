package fr.fantasy.fantasyStatsback.config;

import fr.fantasy.fantasyStatsback.config.helpers.EncryptionHelper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class TokenFilterStateless extends OncePerRequestFilter {



    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain ) throws ServletException, IOException {
        System.out.println("Gilter");
        var cookies = request.getCookies();
        Authentication authentication = null;
        String oAuthValue = null;
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (cookie.getName().equals("OAUTH")) {
                    //do something
                    //value can be retrieved using #cookie.getValue()
                    oAuthValue = cookie.getValue();
                }
            }
        }

        System.out.println("Filter : "+oAuthValue);
        if ( oAuthValue != null ) {
            try {
                var auth = EncryptionHelper.decrypt(EncryptionHelper.secretKey,oAuthValue.getBytes());
                System.out.println(auth);
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
            if ( authentication != null ) {
                SecurityContextHolder.getContext().setAuthentication( authentication );
            }
        }

        filterChain.doFilter( request, response );
    }
}
