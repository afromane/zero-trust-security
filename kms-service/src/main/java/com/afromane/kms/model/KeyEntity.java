package com.afromane.kms.model;

import jakarta.persistence.*;
import java.time.Instant;

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

    public KeyEntity() {}

    public KeyEntity(String keyId, String algorithm, String publicKeyPem, String privateKeyPem, boolean active, Instant createdAt) {
        this.keyId = keyId;
        this.algorithm = algorithm;
        this.publicKeyPem = publicKeyPem;
        this.privateKeyPem = privateKeyPem;
        this.active = active;
        this.createdAt = createdAt;
    }

    public Long getId() { return id; }
    public String getKeyId() { return keyId; }
    public void setKeyId(String keyId) { this.keyId = keyId; }
    public String getAlgorithm() { return algorithm; }
    public void setAlgorithm(String algorithm) { this.algorithm = algorithm; }
    public String getPublicKeyPem() { return publicKeyPem; }
    public void setPublicKeyPem(String publicKeyPem) { this.publicKeyPem = publicKeyPem; }
    public String getPrivateKeyPem() { return privateKeyPem; }
    public void setPrivateKeyPem(String privateKeyPem) { this.privateKeyPem = privateKeyPem; }
    public boolean isActive() { return active; }
    public void setActive(boolean active) { this.active = active; }
    public Instant getCreatedAt() { return createdAt; }
    public void setCreatedAt(Instant createdAt) { this.createdAt = createdAt; }
}
