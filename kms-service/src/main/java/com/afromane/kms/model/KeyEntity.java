package com.afromane.kms.model;

import jakarta.persistence.*;
import java.time.Instant;

/**
 * Entité JPA représentant une clé cryptographique conservée dans la base de données H2 chiffrée.
 * <p>
 * Chaque enregistrement modélise une paire de clés (publique et privée) sous format standard PEM,
 * associée à un algorithme (ex: RSA), un identifiant unique de clé ({@code keyId}) et un statut d'activité.
 * </p>
 *
 * @author afromane
 * @version 1.0.0
 */
@Entity
@Table(name = "kms_keys")
public class KeyEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true, length = 100)
    private String keyId;

    @Column(nullable = false, length = 20)
    private String algorithm;

    @Column(columnDefinition = "TEXT", nullable = false)
    private String publicKeyPem;

    @Column(columnDefinition = "TEXT", nullable = false)
    private String privateKeyPem;

    @Column(nullable = false)
    private boolean active;

    @Column(nullable = false)
    private Instant createdAt;

    /**
     * Constructeur par défaut requis par la spécification JPA.
     */
    public KeyEntity() {}

    /**
     * Construit une nouvelle entité de clé cryptographique prête à être persistée.
     *
     * @param keyId         identifiant unique de la clé (ex: {@code zerotrust-master-key-v1})
     * @param algorithm     nom de l'algorithme asymétrique (ex: {@code RSA})
     * @param publicKeyPem  clé publique encodée en format PEM (X.509)
     * @param privateKeyPem clé privée encodée en format PEM (PKCS#8)
     * @param active        {@code true} si la clé est la clé active pour les nouvelles signatures
     * @param createdAt     date et heure de création de la paire de clés
     */
    public KeyEntity(String keyId, String algorithm, String publicKeyPem, String privateKeyPem, boolean active, Instant createdAt) {
        this.keyId = keyId;
        this.algorithm = algorithm;
        this.publicKeyPem = publicKeyPem;
        this.privateKeyPem = privateKeyPem;
        this.active = active;
        this.createdAt = createdAt;
    }

    /**
     * Renvoie l'identifiant technique en base de données.
     *
     * @return identifiant auto-généré
     */
    public Long getId() { return id; }

    /**
     * Renvoie l'identifiant fonctionnel unique de la clé.
     *
     * @return nom ou alias de la clé
     */
    public String getKeyId() { return keyId; }

    /**
     * Définit l'identifiant fonctionnel de la clé.
     *
     * @param keyId nouvel identifiant
     */
    public void setKeyId(String keyId) { this.keyId = keyId; }

    /**
     * Renvoie l'algorithme utilisé par cette clé.
     *
     * @return nom de l'algorithme (ex: RSA)
     */
    public String getAlgorithm() { return algorithm; }

    /**
     * Définit l'algorithme de la clé.
     *
     * @param algorithm nom de l'algorithme
     */
    public void setAlgorithm(String algorithm) { this.algorithm = algorithm; }

    /**
     * Renvoie la clé publique encodée en PEM.
     *
     * @return chaîne PEM de la clé publique
     */
    public String getPublicKeyPem() { return publicKeyPem; }

    /**
     * Définit la clé publique au format PEM.
     *
     * @param publicKeyPem chaîne PEM de la clé publique
     */
    public void setPublicKeyPem(String publicKeyPem) { this.publicKeyPem = publicKeyPem; }

    /**
     * Renvoie la clé privée encodée en PEM.
     *
     * @return chaîne PEM de la clé privée
     */
    public String getPrivateKeyPem() { return privateKeyPem; }

    /**
     * Définit la clé privée au format PEM.
     *
     * @param privateKeyPem chaîne PEM de la clé privée
     */
    public void setPrivateKeyPem(String privateKeyPem) { this.privateKeyPem = privateKeyPem; }

    /**
     * Indique si la clé est actuellement active pour signer les nouveaux messages.
     *
     * @return {@code true} si active, {@code false} si archivée
     */
    public boolean isActive() { return active; }

    /**
     * Définit l'état d'activité de la clé.
     *
     * @param active nouvel état
     */
    public void setActive(boolean active) { this.active = active; }

    /**
     * Renvoie l'horodatage de création de la clé.
     *
     * @return date et heure de génération
     */
    public Instant getCreatedAt() { return createdAt; }

    /**
     * Définit l'horodatage de création.
     *
     * @param createdAt date et heure
     */
    public void setCreatedAt(Instant createdAt) { this.createdAt = createdAt; }
}
