package com.vishwas.springsecurity.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class JWTAuthenticationFilter extends OncePerRequestFilter {

    // Jwt service
    // Self made class that contains various extracting method from the received token
    private final JwtService jwtService;

    // User-detail service
    private final UserDetailsService userDetailsService;

    // Overriding the method of the OncePerRequestFilter,
    // OncePerRequestFilter is used to server one request per user
    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request,
                                    @NonNull HttpServletResponse response,
                                    @NonNull FilterChain filterChain
    ) throws ServletException, IOException {

        // fetching the header from the request where the header is Authorization.
        final String authHeader = request.getHeader("Authorization");

        // The header of Authorization always starts as "Bearer ...token..."
        // If the token or header is not of Authorization
        // or is null, return to the next filter.
        if(authHeader==null || !authHeader.startsWith("Bearer")){
            filterChain.doFilter(request,response);
            return;
        }

        // Storing the token, here the token is extracted form the header
        // Starting the string from index 7 for extracting the token
        // because the authentication token always began with Bearer
        final String jwtToken=authHeader.substring(7);

        // Extracting the user email from the token.
        // Token sample from https://jwt.io/
        final String userEmail = jwtService.extractUserName(jwtToken);

        // Applying the security for the username received
        // Only apply when the userEmail is not null and is not authorized
        if(userEmail!=null || SecurityContextHolder.getContext().getAuthentication() == null){

            // Fetching the User-details from the UserDetailsService.
            // Here the User object will be returned
            UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail);

            // Check if the received token is valid or not
            if(jwtService.isTokenValid(jwtToken,userDetails)){

                // Generate the authentication token by holding the username and password
                UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
                        userDetails,null,userDetails.getAuthorities()
                );

                // set the authentication token
                authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                // Set the authentication token for the user
                SecurityContextHolder.getContext().setAuthentication(authenticationToken);

            }

        }

        // redirect to the next filter
        filterChain.doFilter(request,response);

    }

}
