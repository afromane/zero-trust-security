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

/**
 * Client HTTP communiquant avec le microservice KMS pour la signature et la vérification des messages Kafka.
 * <p>
 * Ce client optimise les performances par un système de cache mémoire :
 * <ul>
 *   <li><b>Demande de signature :</b> Effectue un appel REST POST vers {@code /api/v1/kms/sign} pour chaque message à émettre.</li>
 *   <li><b>Vérification de signature :</b> Télécharge le trousseau JWKS depuis {@code /.well-known/jwks.json} et
 *   met en cache les clés publiques RSA en RAM. Les vérifications suivantes se font localement sans appel réseau.</li>
 * </ul>
 * </p>
 *
 * @author afromane
 * @version 1.0.0
 */
public class KmsClient {

    private static final Logger log = LoggerFactory.getLogger(KmsClient.class);

    private final RestClient restClient;
    private final ZeroTrustKafkaProperties properties;

    /**
     * Cache mémoire des clés publiques RSA indexées par leur keyId.
     */
    private final Map<String, PublicKey> publicKeyCache = new ConcurrentHashMap<>();

    /**
     * Construit le client KMS avec les propriétés injectées et initialise le {@link RestClient}.
     *
     * @param properties configuration de la sécurité Kafka
     */
    public KmsClient(ZeroTrustKafkaProperties properties) {
        this.properties = properties;
        this.restClient = RestClient.builder()
                .baseUrl(properties.getKmsBaseUrl())
                .build();
    }

    /**
     * DTO interne pour envoyer la requête de signature au KMS.
     *
     * @param keyId      identifiant de la clé
     * @param dataBase64 données brutes encodées en Base64
     */
    public record SignDto(String keyId, String dataBase64) {}

    /**
     * DTO interne représentant la réponse de signature renvoyée par le KMS.
     *
     * @param keyId           identifiant de la clé utilisée
     * @param algorithm       algorithme appliqué
     * @param signatureBase64 signature RSA en Base64
     */
    public record SignResultDto(String keyId, String algorithm, String signatureBase64) {}

    /**
     * Envoie un tableau d'octets au KMS pour obtenir sa signature numérique RSA.
     *
     * @param payload octets du message à signer
     * @return résultat de signature contenant la signature Base64 et le keyId
     */
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

    /**
     * Récupère la clé publique RSA associée au keyId spécifié, depuis le cache mémoire ou via rafraîchissement JWKS.
     *
     * @param keyId identifiant de la clé
     * @return instance {@link PublicKey} RSA prête pour la vérification
     * @throws IllegalStateException si aucune clé publique correspondante n'a pu être obtenue du KMS
     */
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

    /**
     * Télécharge le jeu de clés publiques (JWKS) depuis le serveur KMS et met à jour le cache local en RAM.
     */
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
