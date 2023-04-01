package com.vishwas.springsecurity.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfiguration {

    // @Autowire bean coming from the self-made class JWTAuthenticationFilter
    private final JWTAuthenticationFilter jwtAuthFilter;

    // @Autowire bean coming from the ApplicationConfig
    private final AuthenticationProvider authenticationProvider;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {


        http
                // Cross-Site Request Forgery, inserting the attackers url instead of real one.
                // If our stateless API uses token-based authentication, such as JWT,
                // we don't need CSRF protection, and we must disable it as we saw earlier.
                //However, if our stateless API uses a session cookie authentication,
                // we need to enable CSRF protection.
                .csrf()
                .disable()

                // Provides authorization for the provided request
                .authorizeHttpRequests()

                // Match the url pattern and give permit to all
                .requestMatchers("api/auth/**").permitAll()

                // Can add other url matcher and decide the redirecting based on ROLE
                //.requestMatchers("api/auth/admin/**").hasAnyAuthority("ADMIN")

                // Other than the provided patter above authentication is required.
                .anyRequest().authenticated()

                // Add new configuration
                .and()

                // Making the session stateless and creating new session per request
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)

                // Add new configuration
                .and()

                // Specifying the AuthenticationProvider
                .authenticationProvider(authenticationProvider)

                // Call jwtAuthFilter filter before the UsernamePasswordAuthentication filter
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);


        return http.build();
    }


}


