package com.afromane.security.rest;

import com.afromane.security.rest.interceptor.TokenRelayInterceptor;
import com.afromane.security.rest.validator.AudienceValidator;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.security.web.SecurityFilterChain;

@AutoConfiguration
@EnableWebSecurity
@EnableMethodSecurity
@EnableConfigurationProperties(ZeroTrustRestProperties.class)
@ConditionalOnProperty(prefix = "zerotrust.rest", name = "enabled", havingValue = "true", matchIfMissing = true)
public class ZeroTrustRestAutoConfiguration {

    private final ZeroTrustRestProperties properties;

    public ZeroTrustRestAutoConfiguration(ZeroTrustRestProperties properties) {
        this.properties = properties;
    }

    @Bean
    @ConditionalOnMissingBean
    public SecurityFilterChain zeroTrustSecurityFilterChain(HttpSecurity http, JwtDecoder jwtDecoder) throws Exception {
        String[] permitted = properties.getPermittedPaths().toArray(new String[0]);

        return http
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(permitted).permitAll()
                        .anyRequest().authenticated()
                )
                .oauth2ResourceServer(oauth2 -> oauth2.jwt(jwt -> jwt.decoder(jwtDecoder)))
                .build();
    }

    @Bean
    @ConditionalOnMissingBean
    public JwtDecoder zeroTrustJwtDecoder() {
        NimbusJwtDecoder decoder = NimbusJwtDecoder.withJwkSetUri(properties.getJwkSetUri()).build();

        OAuth2TokenValidator<Jwt> defaultValidator = JwtValidators.createDefault();
        OAuth2TokenValidator<Jwt> audienceValidator = new AudienceValidator(properties.getAudience());
        decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(defaultValidator, audienceValidator));

        return decoder;
    }

    @Bean
    @ConditionalOnMissingBean
    public org.springframework.http.client.ClientHttpRequestInterceptor tokenRelayInterceptor() {
        return new TokenRelayInterceptor();
    }
}
