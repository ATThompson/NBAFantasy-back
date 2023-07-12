package fr.fantasy.fantasyStatsback.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class TokenFilter extends OncePerRequestFilter {


    @Override
    protected void doFilterInternal( HttpServletRequest request, HttpServletResponse response, FilterChain filterChain ) throws ServletException, IOException {
        System.out.println("Internal FIlter");
        String authToken = request.getHeader( "Authorization" );
        if ( authToken != null ) {
            String token = authToken.split( " " )[ 1 ];
            //Authentication authentication = tokenStore.getAuth( token );
            Authentication authentication = null;
            if ( authentication != null ) {
                SecurityContextHolder.getContext().setAuthentication( authentication );
            }
        }

        filterChain.doFilter( request, response );
    }


}