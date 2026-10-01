package com.afromane.security.kafka;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Propriétés de configuration externalisées pour le starter {@code zerotrust-kafka-signing}.
 * <p>
 * Ces propriétés sont modifiables dans le fichier {@code application.yml} sous le préfixe {@code zerotrust.kafka}.
 * </p>
 *
 * @author afromane
 * @version 1.0.0
 */
@ConfigurationProperties(prefix = "zerotrust.kafka")
public class ZeroTrustKafkaProperties {

    /**
     * Active ou désactive l'auto-configuration de la sécurité Zero Trust pour Kafka.
     * Valeur par défaut : {@code true}.
     */
    private boolean enabled = true;

    /**
     * URL de base du microservice KMS interne hébergeant les clés de signature et le JWKS.
     * Valeur par défaut : {@code http://localhost:8085}.
     */
    private String kmsBaseUrl = "http://localhost:8085";

    /**
     * Active la signature cryptographique RSA automatique des messages publiés par les producteurs.
     * Valeur par défaut : {@code true}.
     */
    private boolean signingEnabled = true;

    /**
     * Active la vérification automatique de la signature RSA à la réception par les consommateurs.
     * Valeur par défaut : {@code true}.
     */
    private boolean verificationEnabled = true;

    /**
     * Identifiant de la clé de signature spécifique à utiliser (optionnel, la clé active est utilisée par défaut).
     */
    private String keyId;

    /**
     * Nom de l'en-tête Kafka transportant la signature numérique RSA en Base64.
     * Valeur par défaut : {@code X-Signature-RSA}.
     */
    private String signatureHeaderName = "X-Signature-RSA";

    /**
     * Nom de l'en-tête Kafka transportant l'identifiant de la clé ayant servi à signer.
     * Valeur par défaut : {@code X-Key-Id}.
     */
    private String keyIdHeaderName = "X-Key-Id";

    /**
     * Indique si la sécurité Kafka est activée.
     *
     * @return {@code true} si activée
     */
    public boolean isEnabled() { return enabled; }

    /**
     * Active ou désactive le starter Kafka.
     *
     * @param enabled booléen d'activation
     */
    public void setEnabled(boolean enabled) { this.enabled = enabled; }

    /**
     * Renvoie l'URL de base du KMS.
     *
     * @return URL du KMS
     */
    public String getKmsBaseUrl() { return kmsBaseUrl; }

    /**
     * Définit l'URL de base du KMS.
     *
     * @param kmsBaseUrl nouvelle URL
     */
    public void setKmsBaseUrl(String kmsBaseUrl) { this.kmsBaseUrl = kmsBaseUrl; }

    /**
     * Indique si la signature des messages sortants est activée.
     *
     * @return {@code true} si active
     */
    public boolean isSigningEnabled() { return signingEnabled; }

    /**
     * Active ou désactive la signature automatique à l'envoi.
     *
     * @param signingEnabled booléen
     */
    public void setSigningEnabled(boolean signingEnabled) { this.signingEnabled = signingEnabled; }

    /**
     * Indique si la vérification de signature à la réception est activée.
     *
     * @return {@code true} si active
     */
    public boolean isVerificationEnabled() { return verificationEnabled; }

    /**
     * Active ou désactive la vérification automatique à la réception.
     *
     * @param verificationEnabled booléen
     */
    public void setVerificationEnabled(boolean verificationEnabled) { this.verificationEnabled = verificationEnabled; }

    /**
     * Renvoie l'identifiant de clé souhaité pour signer.
     *
     * @return identifiant de clé ou {@code null}
     */
    public String getKeyId() { return keyId; }

    /**
     * Définit l'identifiant de clé pour la signature.
     *
     * @param keyId identifiant de la clé
     */
    public void setKeyId(String keyId) { this.keyId = keyId; }

    /**
     * Renvoie le nom de l'en-tête contenant la signature RSA.
     *
     * @return nom du header
     */
    public String getSignatureHeaderName() { return signatureHeaderName; }

    /**
     * Définit le nom de l'en-tête pour la signature.
     *
     * @param signatureHeaderName nom du header
     */
    public void setSignatureHeaderName(String signatureHeaderName) { this.signatureHeaderName = signatureHeaderName; }

    /**
     * Renvoie le nom de l'en-tête contenant le keyId.
     *
     * @return nom du header
     */
    public String getKeyIdHeaderName() { return keyIdHeaderName; }

    /**
     * Définit le nom de l'en-tête pour le keyId.
     *
     * @param keyIdHeaderName nom du header
     */
    public void setKeyIdHeaderName(String keyIdHeaderName) { this.keyIdHeaderName = keyIdHeaderName; }
}
