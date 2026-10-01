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

public class KafkaSignatureVerificationInterceptor<K, V> implements RecordInterceptor<K, V> {

    private static final Logger log = LoggerFactory.getLogger(KafkaSignatureVerificationInterceptor.class);

    private final KmsClient kmsClient;
    private final ZeroTrustKafkaProperties properties;

    public KafkaSignatureVerificationInterceptor(KmsClient kmsClient, ZeroTrustKafkaProperties properties) {
        this.kmsClient = kmsClient;
        this.properties = properties;
    }

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
