package com.afromane.security.kafka.interceptor;

import com.afromane.security.kafka.ZeroTrustKafkaProperties;
import com.afromane.security.kafka.client.KmsClient;
import org.apache.kafka.clients.consumer.Consumer;
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.apache.kafka.common.header.Header;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.kafka.listener.RecordInterceptor;

import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Base64;

/**
 * Intercepteur automatique branché sur les conteneurs d'écoute Kafka (Spring Kafka {@link RecordInterceptor}).
 * <p>
 * Ce composant implémente la barrière d'intégrité Zero Trust pour tous les messages entrants :
 * <ol>
 *   <li>Vérifie la présence de l'en-tête {@code X-Signature-RSA}.</li>
 *   <li>Récupère la clé publique RSA associée depuis le cache mémoire du {@link KmsClient}.</li>
 *   <li>Vérifie mathématiquement que la signature RSA correspond bien au payload reçu.</li>
 *   <li><b>En cas de succès :</b> Transmet le message au listener métier {@code @KafkaListener}.</li>
 *   <li><b>En cas d'échec :</b> Bloque le message et lève une {@link SecurityException}, empêchant tout traitement d'un message altéré.</li>
 * </ol>
 * </p>
 *
 * @param <K> type de la clé Kafka
 * @param <V> type de la valeur du message Kafka
 *
 * @author afromane
 * @version 1.0.0
 */
public class KafkaSignatureVerificationInterceptor<K, V> implements RecordInterceptor<K, V> {

    private static final Logger log = LoggerFactory.getLogger(KafkaSignatureVerificationInterceptor.class);

    private final KmsClient kmsClient;
    private final ZeroTrustKafkaProperties properties;

    /**
     * Construit l'intercepteur de vérification avec le client KMS et les propriétés.
     *
     * @param kmsClient  client KMS pour récupérer les clés publiques
     * @param properties configuration de la vérification
     */
    public KafkaSignatureVerificationInterceptor(KmsClient kmsClient, ZeroTrustKafkaProperties properties) {
        this.kmsClient = kmsClient;
        this.properties = properties;
    }

    /**
     * Intercepte chaque enregistrement consommé avant qu'il n'atteigne la méthode annotée {@code @KafkaListener}.
     *
     * @param record   enregistrement Kafka reçu
     * @param consumer instance du consommateur Kafka sous-jacent
     * @return l'enregistrement validé pour traitement par l'application
     * @throws SecurityException si la signature est absente, invalide ou si le contenu a été altéré
     */
    @Override
    public ConsumerRecord<K, V> intercept(ConsumerRecord<K, V> record, Consumer<K, V> consumer) {
        if (!properties.isVerificationEnabled()) {
            return record;
        }

        Header sigHeader = record.headers().lastHeader(properties.getSignatureHeaderName());
        Header keyIdHeader = record.headers().lastHeader(properties.getKeyIdHeaderName());

        if (sigHeader == null || sigHeader.value() == null) {
            log.error("VIOLATION ZERO TRUST : Message rejeté sur le topic [{}] (partition {}, offset {}). En-tête de signature RSA '{}' absent !",
                    record.topic(), record.partition(), record.offset(), properties.getSignatureHeaderName());
            throw new SecurityException("Zero Trust Violation : Message Kafka sans signature RSA !");
        }

        String signatureBase64 = new String(sigHeader.value(), StandardCharsets.UTF_8);
        String keyId = (keyIdHeader != null && keyIdHeader.value() != null)
                ? new String(keyIdHeader.value(), StandardCharsets.UTF_8)
                : null;

        try {
            byte[] signatureBytes = Base64.getDecoder().decode(signatureBase64);
            byte[] payloadBytes = extractPayloadBytes(record.value());

            PublicKey publicKey = kmsClient.getPublicKey(keyId);

            Signature verifier = Signature.getInstance("SHA256withRSA");
            verifier.initVerify(publicKey);
            verifier.update(payloadBytes);

            boolean valid = verifier.verify(signatureBytes);
            if (!valid) {
                log.error("VIOLATION ZERO TRUST : Signature RSA invalide ou payload altéré pour le message sur topic [{}] !", record.topic());
                throw new SecurityException("Zero Trust Violation : Signature RSA invalide, message altéré ou falsifié !");
            }

            log.debug("Validation Zero Trust réussie pour le message Kafka sur topic [{}] (Clé: {})", record.topic(), keyId);
            return record;
        } catch (SecurityException se) {
            throw se;
        } catch (Exception e) {
            log.error("Erreur lors de la vérification de la signature RSA : {}", e.getMessage(), e);
            throw new SecurityException("Échec critique de vérification de signature Kafka", e);
        }
    }

    /**
     * Extrait les octets de la charge utile de manière sûre.
     */
    private byte[] extractPayloadBytes(Object value) {
        if (value == null) {
            return new byte[0];
        }
        if (value instanceof byte[] bytes) {
            return bytes;
        }
        if (value instanceof String str) {
            return str.getBytes(StandardCharsets.UTF_8);
        }
        return value.toString().getBytes(StandardCharsets.UTF_8);
    }
}
