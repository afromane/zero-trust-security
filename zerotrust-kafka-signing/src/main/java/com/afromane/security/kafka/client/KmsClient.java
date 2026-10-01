package com.afromane.security.kafka.client;

import com.afromane.security.kafka.ZeroTrustKafkaProperties;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.web.client.RestClient;

import java.security.PublicKey;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class KmsClient {

    private static final Logger log = LoggerFactory.getLogger(KmsClient.class);

    private final RestClient restClient;
    private final ZeroTrustKafkaProperties properties;
    private final Map<String, PublicKey> publicKeyCache = new ConcurrentHashMap<>();

    public KmsClient(ZeroTrustKafkaProperties properties) {
        this.properties = properties;
        this.restClient = RestClient.builder()
                .baseUrl(properties.getKmsBaseUrl())
                .build();
    }

    public record SignDto(String keyId, String dataBase64) {}
    public record SignResultDto(String keyId, String algorithm, String signatureBase64) {}

    public SignResultDto requestSignature(byte[] payload) {
        String base64Payload = Base64.getEncoder().encodeToString(payload);
        SignDto request = new SignDto(properties.getKeyId(), base64Payload);

        return restClient.post()
                .uri("/api/v1/kms/sign")
                .contentType(MediaType.APPLICATION_JSON)
                .body(request)
                .retrieve()
                .body(SignResultDto.class);
    }

    public PublicKey getPublicKey(String keyId) {
        if (keyId != null && publicKeyCache.containsKey(keyId)) {
            return publicKeyCache.get(keyId);
        }

        refreshPublicKeys();

        if (keyId != null && publicKeyCache.containsKey(keyId)) {
            return publicKeyCache.get(keyId);
        }

        return publicKeyCache.values().stream().findFirst()
                .orElseThrow(() -> new IllegalStateException("Aucune clé publique RSA disponible depuis le KMS (" + properties.getKmsBaseUrl() + ")"));
    }

    public synchronized void refreshPublicKeys() {
        try {
            log.info("Téléchargement du JWKS depuis le KMS : {}/.well-known/jwks.json", properties.getKmsBaseUrl());
            String jwksJson = restClient.get()
                    .uri("/.well-known/jwks.json")
                    .accept(MediaType.APPLICATION_JSON)
                    .retrieve()
                    .body(String.class);

            if (jwksJson != null) {
                JWKSet jwkSet = JWKSet.parse(jwksJson);
                for (JWK jwk : jwkSet.getKeys()) {
                    if (jwk instanceof RSAKey rsaKey) {
                        publicKeyCache.put(rsaKey.getKeyID(), rsaKey.toPublicKey());
                    }
                }
                log.info("Clés publiques RSA rafraîchies en mémoire depuis le KMS : {}", publicKeyCache.keySet());
            }
        } catch (Exception e) {
            log.error("Échec du rafraîchissement des clés publiques depuis le KMS : {}", e.getMessage());
            throw new RuntimeException("Impossible de contacter le KMS pour récupérer le JWKS", e);
        }
    }
}
