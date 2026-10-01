package com.afromane.security.kafka;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "zerotrust.kafka")
public class ZeroTrustKafkaProperties {

    /**
     * Active ou désactive la sécurité Zero Trust pour Kafka.
     */
    private boolean enabled = true;

    /**
     * URL de base du microservice KMS interne.
     */
    private String kmsBaseUrl = "http://localhost:8085";

    /**
     * Active la signature automatique des messages émis par les producteurs.
     */
    private boolean signingEnabled = true;

    /**
     * Active la vérification automatique de signature à la réception par les consommateurs.
     */
    private boolean verificationEnabled = true;

    /**
     * Identifiant de la clé de signature (optionnel, utilise la clé active du KMS par défaut).
     */
    private String keyId;

    /**
     * Nom de l'en-tête Kafka transportant la signature RSA.
     */
    private String signatureHeaderName = "X-Signature-RSA";

    /**
     * Nom de l'en-tête Kafka transportant l'identifiant de la clé.
     */
    private String keyIdHeaderName = "X-Key-Id";

    public boolean isEnabled() { return enabled; }
    public void setEnabled(boolean enabled) { this.enabled = enabled; }
    public String getKmsBaseUrl() { return kmsBaseUrl; }
    public void setKmsBaseUrl(String kmsBaseUrl) { this.kmsBaseUrl = kmsBaseUrl; }
    public boolean isSigningEnabled() { return signingEnabled; }
    public void setSigningEnabled(boolean signingEnabled) { this.signingEnabled = signingEnabled; }
    public boolean isVerificationEnabled() { return verificationEnabled; }
    public void setVerificationEnabled(boolean verificationEnabled) { this.verificationEnabled = verificationEnabled; }
    public String getKeyId() { return keyId; }
    public void setKeyId(String keyId) { this.keyId = keyId; }
    public String getSignatureHeaderName() { return signatureHeaderName; }
    public void setSignatureHeaderName(String signatureHeaderName) { this.signatureHeaderName = signatureHeaderName; }
    public String getKeyIdHeaderName() { return keyIdHeaderName; }
    public void setKeyIdHeaderName(String keyIdHeaderName) { this.keyIdHeaderName = keyIdHeaderName; }
}
