package com.afromane.security.rest;

import com.afromane.security.rest.interceptor.TokenRelayInterceptor;
import com.afromane.security.rest.validator.AudienceValidator;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Classe d'auto-configuration Spring Boot pour la sécurité Web Zero Trust.
 * <p>
 * Déclare automatiquement :
 * <ul>
 *   <li>Une {@link SecurityFilterChain} verrouillant l'ensemble des routes en mode Stateless.</li>
 *   <li>Un {@link JwtDecoder} configuré avec le point de terminaison JWKS et le validateur d'audience.</li>
 *   <li>L'intercepteur {@link TokenRelayInterceptor} pour la propagation inter-services.</li>
 * </ul>
 * </p>
 *
 * @author afromane
 * @version 1.0.0
 */
@AutoConfiguration
@EnableWebSecurity
@EnableMethodSecurity
@EnableConfigurationProperties(ZeroTrustRestProperties.class)
@ConditionalOnProperty(prefix = "zerotrust.rest", name = "enabled", havingValue = "true", matchIfMissing = true)
public class ZeroTrustRestAutoConfiguration {

    private final ZeroTrustRestProperties properties;

    /**
     * Initialise la classe d'auto-configuration avec les propriétés injectées.
     *
     * @param properties configuration de la sécurité REST
     */
    public ZeroTrustRestAutoConfiguration(ZeroTrustRestProperties properties) {
        this.properties = properties;
    }

    /**
     * Configure la chaîne de filtres Spring Security.
     * <ul>
     *   <li>Désactive CSRF (inutile en mode API stateless avec jetons Bearer).</li>
     *   <li>Force la politique de session sur {@link SessionCreationPolicy#STATELESS}.</li>
     *   <li>Autorise les routes configurées dans {@code permittedPaths}.</li>
     *   <li>Exige une authentification pour toutes les autres requêtes.</li>
     *   <li>Configure le serveur de ressources OAuth2 avec validation JWT.</li>
     * </ul>
     *
     * @param http       constructeur de sécurité HTTP
     * @param jwtDecoder décodeur JWT configuré
     * @return instance configurée de {@link SecurityFilterChain}
     * @throws Exception en cas d'erreur de configuration
     */
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

    /**
     * Instancie et configure le décodeur JWT {@link NimbusJwtDecoder}.
     * <p>
     * Se connecte à l'URL JWKS configurée pour télécharger les clés publiques RSA
     * et applique la validation par défaut (timestamps, signature) ainsi que le validateur d'audience.
     * </p>
     *
     * @return décodeur JWT prêt à l'emploi
     */
    @Bean
    @ConditionalOnMissingBean
    public JwtDecoder zeroTrustJwtDecoder() {
        NimbusJwtDecoder decoder = NimbusJwtDecoder.withJwkSetUri(properties.getJwkSetUri()).build();

        OAuth2TokenValidator<Jwt> defaultValidator = JwtValidators.createDefault();
        OAuth2TokenValidator<Jwt> audienceValidator = new AudienceValidator(properties.getAudience());
        decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(defaultValidator, audienceValidator));

        return decoder;
    }

    /**
     * Fournit un intercepteur HTTP pour la propagation automatique des jetons d'accès.
     *
     * @return instance de {@link ClientHttpRequestInterceptor}
     */
    @Bean
    @ConditionalOnMissingBean
    public ClientHttpRequestInterceptor tokenRelayInterceptor() {
        return new TokenRelayInterceptor();
    }
}
