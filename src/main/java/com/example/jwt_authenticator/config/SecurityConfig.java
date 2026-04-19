package com.example.jwt_authenticator.config;

import com.example.jwt_authenticator.config.properties.PublicPathsProperties;
import com.example.jwt_authenticator.security.JsonAuthenticationEntryPoint;
import com.example.jwt_authenticator.security.JsonAccessDeniedHandler;
import com.example.jwt_authenticator.security.JwtAuthenticationFilter;
import com.example.jwt_authenticator.security.OAuth2SuccessHandler;
import com.example.jwt_authenticator.service.CustomOAuth2UserService;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.core.env.Profiles;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.filter.ForwardedHeaderFilter;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * Central Spring Security configuration.
 *
 * Key enterprise improvements over the original:
 *  1. @Lazy removed — circular dependency resolved by JwtAuthenticationFailureHandler
 *  2. AuthenticationManager exposed as a bean (required by AuthService)
 *  3. Whitelist sourced from PublicPathsProperties (single source of truth)
 *  4. Swagger endpoints only exposed outside the "prod" profile
 *  5. Security response headers added (HSTS, CSP, X-Frame-Options, Referrer-Policy)
 *  6. OAuth2 failure handler uses a generic message — no internal exception leaking
 *  7. ForwardedHeaderFilter registered to handle X-Forwarded-For safely
 *  8. @EnableMethodSecurity enabled for @PreAuthorize / @Secured on service methods
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final JsonAuthenticationEntryPoint authenticationEntryPoint;
    private final JsonAccessDeniedHandler accessDeniedHandler;
    private final CorsConfigurationSource corsConfigurationSource;
    private final CustomOAuth2UserService customOAuth2UserService;
    private final OAuth2SuccessHandler oAuth2SuccessHandler;
    private final PublicPathsProperties publicPaths;
    private final Environment environment;

    public SecurityConfig(
            JwtAuthenticationFilter jwtAuthenticationFilter,   // no @Lazy needed anymore
            JsonAuthenticationEntryPoint authenticationEntryPoint,
            JsonAccessDeniedHandler accessDeniedHandler,
            CorsConfigurationSource corsConfigurationSource,
            CustomOAuth2UserService customOAuth2UserService,
            OAuth2SuccessHandler oAuth2SuccessHandler,
            PublicPathsProperties publicPaths,
            Environment environment
    ) {
        this.jwtAuthenticationFilter    = jwtAuthenticationFilter;
        this.authenticationEntryPoint   = authenticationEntryPoint;
        this.accessDeniedHandler        = accessDeniedHandler;
        this.corsConfigurationSource    = corsConfigurationSource;
        this.customOAuth2UserService    = customOAuth2UserService;
        this.oAuth2SuccessHandler       = oAuth2SuccessHandler;
        this.publicPaths                = publicPaths;
        this.environment                = environment;
    }

    // -------------------------------------------------------------------------
    // Beans
    // -------------------------------------------------------------------------

    @Bean
    public PasswordEncoder passwordEncoder() {
        // Cost factor 12 is the current enterprise default (OWASP 2024).
        // Increase to 13-14 on hardware that can sustain it.
        return new BCryptPasswordEncoder(12);
    }

    /**
     * Exposes AuthenticationManager so AuthService can call authenticate()
     * without pulling SecurityConfig into its dependency graph.
     */
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    /**
     * Handles X-Forwarded-For and X-Forwarded-Proto transparently.
     * With this filter registered, request.getRemoteAddr() returns the real client IP
     * and RefreshTokenService.extractIp() can be simplified to just getRemoteAddr().
     *
     * Only trust these headers if your reverse proxy/load-balancer sets them reliably.
     */
    @Bean
    public ForwardedHeaderFilter forwardedHeaderFilter() {
        return new ForwardedHeaderFilter();
    }

    // -------------------------------------------------------------------------
    // Security filter chain
    // -------------------------------------------------------------------------

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        boolean isProd = environment.acceptsProfiles(Profiles.of("prod"));

        http
                // --- CORS ---
                .cors(cors -> cors.configurationSource(corsConfigurationSource))

                // --- CSRF ---
                // Disabled for the JWT API surface. The OAuth2 flow creates a transient
                // session only to carry the OIDC "state" parameter (CSRF protection for
                // the redirect); this is handled by Spring Security internally.
                .csrf(csrf -> csrf.disable())

                // --- Sessions ---
                // IF_REQUIRED: Spring OAuth2 needs a temporary session to store the
                // "state" anti-CSRF parameter during the Google redirect.
                // All other endpoints are effectively stateless (JWT).
                .sessionManagement(sm -> sm
                        .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                )

                // --- Exception handling ---
                .exceptionHandling(ex -> ex
                        .authenticationEntryPoint(authenticationEntryPoint)
                        .accessDeniedHandler(accessDeniedHandler)
                )

                // --- HTTP security headers ---
                .headers(headers -> headers
                        // Prevent clickjacking
                        .frameOptions(HeadersConfigurer.FrameOptionsConfig::deny)
                        // Force HTTPS for 1 year (prod only — avoids breaking local dev with HTTP)
                        .httpStrictTransportSecurity(hsts -> hsts
                                .includeSubDomains(true)
                                .maxAgeInSeconds(isProd ? 31_536_000 : 0)
                        )
                        // Tight CSP — tighten further once you know all your script/style sources
                        .contentSecurityPolicy(csp -> csp
                                .policyDirectives("default-src 'self'; frame-ancestors 'none'")
                        )
                        // Referrer: no URL leakage to third parties
                        .referrerPolicy(rp -> rp
                                .policy(ReferrerPolicyHeaderWriter.ReferrerPolicy.STRICT_ORIGIN_WHEN_CROSS_ORIGIN)
                        )
                        // Prevent MIME sniffing
                        .contentTypeOptions(ct -> {})
                )

                // --- Authorization rules ---
                .authorizeHttpRequests(auth -> {
                    // Public exact paths — sourced from PublicPathsProperties
                    auth.requestMatchers(publicPaths.exact().toArray(String[]::new)).permitAll();

                    // Public prefix paths
                    for (String prefix : publicPaths.prefixes()) {
                        if (!isProd || (!prefix.startsWith("/swagger-ui") && !prefix.startsWith("/v3/api-docs"))) {
                            auth.requestMatchers(prefix + "/**").permitAll();
                        }
                    }

                    // Role-based
                    auth.requestMatchers("/api/admin/**").hasRole("ADMIN");

                    // Everything else requires authentication
                    auth.anyRequest().authenticated();
                })

                // --- OAuth2 login ---
                .oauth2Login(oauth2 -> oauth2
                        .userInfoEndpoint(ui -> ui.userService(customOAuth2UserService))
                        .successHandler(oAuth2SuccessHandler)
                        .failureHandler((req, res, ex) -> {
                            // Never expose the internal exception message to the client.
                            // Log it server-side for debugging.
                            String safeError = URLEncoder.encode("oauth2_authentication_failed", StandardCharsets.UTF_8);
                            res.sendRedirect("/api/auth/oauth2/failure?error=" + safeError);
                        })
                )

                // --- JWT filter ---
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
}