package com.afromane.security.rest;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.ArrayList;
import java.util.List;

/**
 * Propriétés de configuration externalisées pour le starter {@code zerotrust-rest-security}.
 * <p>
 * Ces propriétés sont modifiables dans le fichier {@code application.yml} sous le préfixe {@code zerotrust.rest}.
 * </p>
 *
 * @author afromane
 * @version 1.0.0
 */
@ConfigurationProperties(prefix = "zerotrust.rest")
public class ZeroTrustRestProperties {

    /**
     * Active ou désactive l'auto-configuration de la sécurité Zero Trust REST.
     * Valeur par défaut : {@code true}.
     */
    private boolean enabled = true;

    /**
     * URL du point de terminaison JWKS fournissant les clés publiques RSA pour décoder et valider les JWT.
     * Valeur par défaut : {@code http://localhost:8085/.well-known/jwks.json}.
     */
    private String jwkSetUri = "http://localhost:8085/.well-known/jwks.json";

    /**
     * Nom du service / Audience obligatoire attendue dans le claim {@code aud} du token JWT.
     * Protège le microservice contre les attaques par rejeu de tokens émis pour un autre service.
     */
    private String audience;

    /**
     * Liste des chemins publics exemptés d'authentification (ex: sondes de santé Actuator).
     * Valeur par défaut : {@code ["/actuator/health", "/actuator/info", "/error"]}.
     */
    private List<String> permittedPaths = new ArrayList<>(List.of(
            "/actuator/health",
            "/actuator/info",
            "/error"
    ));

    /**
     * Indique si le module de sécurité est activé.
     *
     * @return {@code true} si activé
     */
    public boolean isEnabled() { return enabled; }

    /**
     * Active ou désactive le starter.
     *
     * @param enabled booléen d'activation
     */
    public void setEnabled(boolean enabled) { this.enabled = enabled; }

    /**
     * Renvoie l'URI du JWKS.
     *
     * @return URL complète vers le fichier JSON des clés
     */
    public String getJwkSetUri() { return jwkSetUri; }

    /**
     * Définit l'URI du JWKS.
     *
     * @param jwkSetUri nouvelle URL
     */
    public void setJwkSetUri(String jwkSetUri) { this.jwkSetUri = jwkSetUri; }

    /**
     * Renvoie l'audience attendue pour ce microservice.
     *
     * @return nom de l'audience
     */
    public String getAudience() { return audience; }

    /**
     * Définit l'audience attendue.
     *
     * @param audience nom de l'audience (ex: {@code order-service})
     */
    public void setAudience(String audience) { this.audience = audience; }

    /**
     * Renvoie la liste des routes HTTP autorisées sans authentification.
     *
     * @return liste des chemins exemptés
     */
    public List<String> getPermittedPaths() { return permittedPaths; }

    /**
     * Définit les routes publiques.
     *
     * @param permittedPaths nouvelle liste de chemins
     */
    public void setPermittedPaths(List<String> permittedPaths) { this.permittedPaths = permittedPaths; }
}
