package com.afromane.security.rest;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.ArrayList;
import java.util.List;

@ConfigurationProperties(prefix = "zerotrust.rest")
public class ZeroTrustRestProperties {

    /**
     * Active ou désactive l'auto-configuration Zero Trust REST.
     */
    private boolean enabled = true;

    /**
     * URL du point de terminaison JWKS (ex: microservice KMS local ou distant).
     */
    private String jwkSetUri = "http://localhost:8085/.well-known/jwks.json";

    /**
     * Nom du service / Audience attendue dans le claim "aud" du token JWT.
     */
    private String audience;

    /**
     * Liste des chemins publics exemptés d'authentification (ex: /actuator/health).
     */
    private List<String> permittedPaths = new ArrayList<>(List.of(
            "/actuator/health",
            "/actuator/info",
            "/error"
    ));

    public boolean isEnabled() { return enabled; }
    public void setEnabled(boolean enabled) { this.enabled = enabled; }
    public String getJwkSetUri() { return jwkSetUri; }
    public void setJwkSetUri(String jwkSetUri) { this.jwkSetUri = jwkSetUri; }
    public String getAudience() { return audience; }
    public void setAudience(String audience) { this.audience = audience; }
    public List<String> getPermittedPaths() { return permittedPaths; }
    public void setPermittedPaths(List<String> permittedPaths) { this.permittedPaths = permittedPaths; }
}
