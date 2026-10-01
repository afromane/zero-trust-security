package com.afromane.kms.service;

import com.afromane.kms.dto.SignResponse;
import com.afromane.kms.dto.VerifyResponse;
import com.afromane.kms.model.KeyEntity;
import com.afromane.kms.repository.KeyRepository;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class KeyManagementService {

    private static final Logger log = LoggerFactory.getLogger(KeyManagementService.class);
    private static final String ALGORITHM = "RSA";
    private static final String SIGNATURE_ALGORITHM = "SHA256withRSA";

    private final KeyRepository keyRepository;
    private final String defaultKeyId;
    private final int defaultKeySize;

    private final Map<String, KeyPair> inMemoryKeyCache = new ConcurrentHashMap<>();
    private volatile String activeKeyId;

    public KeyManagementService(
            KeyRepository keyRepository,
            @Value("${kms.default-key-id:zerotrust-master-key-v1}") String defaultKeyId,
            @Value("${kms.default-key-size:2048}") int defaultKeySize) {
        this.keyRepository = keyRepository;
        this.defaultKeyId = defaultKeyId;
        this.defaultKeySize = defaultKeySize;
    }

    @PostConstruct
    @Transactional
    public void init() {
        log.info("Initialisation du service KMS et du trousseau de clés RSA...");

        Optional<KeyEntity> existingActiveKey = keyRepository.findFirstByActiveTrueOrderByCreatedAtDesc();

        if (existingActiveKey.isPresent()) {
            KeyEntity entity = existingActiveKey.get();
            log.info("Clé RSA active trouvée dans la base H2 chiffrée. Chargement en mémoire RAM (KeyId: {})...", entity.getKeyId());
            try {
                KeyPair keyPair = restoreKeyPairFromPem(entity.getPublicKeyPem(), entity.getPrivateKeyPem());
                inMemoryKeyCache.put(entity.getKeyId(), keyPair);
                this.activeKeyId = entity.getKeyId();
                log.info("Clé RSA [{}] restaurée avec succès en mémoire vive !", entity.getKeyId());
            } catch (Exception e) {
                log.error("Échec critique lors de la restauration de la clé RSA depuis H2 : {}", e.getMessage(), e);
                throw new IllegalStateException("Impossible de charger la clé depuis la base chiffrée H2", e);
            }
        } else {
            log.info("Aucune clé trouvée. Génération d'une nouvelle paire de clés RSA ({} bits)...", defaultKeySize);
            try {
                KeyPair newKeyPair = generateRsaKeyPair(defaultKeySize);
                String publicKeyPem = toPem("PUBLIC KEY", newKeyPair.getPublic().getEncoded());
                String privateKeyPem = toPem("PRIVATE KEY", newKeyPair.getPrivate().getEncoded());

                KeyEntity entity = new KeyEntity(
                        defaultKeyId,
                        ALGORITHM,
                        publicKeyPem,
                        privateKeyPem,
                        true,
                        Instant.now()
                );

                keyRepository.save(entity);
                inMemoryKeyCache.put(defaultKeyId, newKeyPair);
                this.activeKeyId = defaultKeyId;

                log.info("Nouvelle paire de clés RSA générée, persistée dans H2 chiffré et chargée en RAM avec KeyId: {}", defaultKeyId);
            } catch (Exception e) {
                log.error("Échec critique lors de la génération de la clé RSA initiale : {}", e.getMessage(), e);
                throw new IllegalStateException("Impossible d'initialiser la clé RSA", e);
            }
        }
    }

    public SignResponse sign(String keyId, byte[] data) {
        String targetKeyId = (keyId != null && !keyId.isBlank()) ? keyId : this.activeKeyId;
        KeyPair keyPair = inMemoryKeyCache.get(targetKeyId);

        if (keyPair == null) {
            throw new IllegalArgumentException("Clé RSA introuvable en mémoire pour KeyId: " + targetKeyId);
        }

        try {
            Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
            signature.initSign(keyPair.getPrivate());
            signature.update(data);
            byte[] signedBytes = signature.sign();

            return new SignResponse(
                    targetKeyId,
                    SIGNATURE_ALGORITHM,
                    Base64.getEncoder().encodeToString(signedBytes)
            );
        } catch (Exception e) {
            throw new RuntimeException("Erreur lors de la signature cryptographique RSA : " + e.getMessage(), e);
        }
    }

    public VerifyResponse verify(String keyId, byte[] data, byte[] signatureBytes) {
        String targetKeyId = (keyId != null && !keyId.isBlank()) ? keyId : this.activeKeyId;
        KeyPair keyPair = inMemoryKeyCache.get(targetKeyId);

        if (keyPair == null) {
            return new VerifyResponse(targetKeyId, false, "Clé inconnue pour la vérification");
        }

        try {
            Signature verifier = Signature.getInstance(SIGNATURE_ALGORITHM);
            verifier.initVerify(keyPair.getPublic());
            verifier.update(data);
            boolean isValid = verifier.verify(signatureBytes);

            return new VerifyResponse(targetKeyId, isValid, isValid ? "Signature valide" : "Signature falsifiée ou invalide");
        } catch (Exception e) {
            return new VerifyResponse(targetKeyId, false, "Erreur de validation: " + e.getMessage());
        }
    }

    public JWKSet getJwkSet() {
        List<JWK> jwkList = new ArrayList<>();

        for (Map.Entry<String, KeyPair> entry : inMemoryKeyCache.entrySet()) {
            PublicKey pub = entry.getValue().getPublic();
            if (pub instanceof RSAPublicKey rsaPub) {
                RSAKey jwk = new RSAKey.Builder(rsaPub)
                        .keyUse(KeyUse.SIGNATURE)
                        .algorithm(JWSAlgorithm.RS256)
                        .keyID(entry.getKey())
                        .build();
                jwkList.add(jwk);
            }
        }

        return new JWKSet(jwkList);
    }

    public String getActiveKeyId() {
        return activeKeyId;
    }

    private KeyPair generateRsaKeyPair(int keySize) throws NoSuchAlgorithmException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance(ALGORITHM);
        generator.initialize(keySize, new SecureRandom());
        return generator.generateKeyPair();
    }

    private KeyPair restoreKeyPairFromPem(String publicPem, String privatePem) throws Exception {
        byte[] publicBytes = decodePem(publicPem);
        byte[] privateBytes = decodePem(privatePem);

        KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
        PublicKey publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(publicBytes));
        PrivateKey privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privateBytes));

        return new KeyPair(publicKey, privateKey);
    }

    private String toPem(String type, byte[] data) {
        String base64 = Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(data);
        return "-----BEGIN " + type + "-----\n" + base64 + "\n-----END " + type + "-----\n";
    }

    private byte[] decodePem(String pem) {
        String clean = pem
                .replaceAll("-----BEGIN [A-Z ]+-----", "")
                .replaceAll("-----END [A-Z ]+-----", "")
                .replaceAll("\\s", "");
        return Base64.getDecoder().decode(clean);
    }
}
