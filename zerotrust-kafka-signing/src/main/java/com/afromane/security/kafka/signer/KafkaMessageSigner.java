package com.afromane.security.kafka.signer;

import com.afromane.security.kafka.ZeroTrustKafkaProperties;
import com.afromane.security.kafka.client.KmsClient;
import org.apache.kafka.clients.producer.ProducerRecord;
import org.apache.kafka.common.header.Headers;

import java.nio.charset.StandardCharsets;

public class KafkaMessageSigner {

    private final KmsClient kmsClient;
    private final ZeroTrustKafkaProperties properties;

    public KafkaMessageSigner(KmsClient kmsClient, ZeroTrustKafkaProperties properties) {
        this.kmsClient = kmsClient;
        this.properties = properties;
    }

    /**
     * Signe le payload d'un ProducerRecord et injecte la signature RSA dans ses en-têtes.
     */
    public <K, V> ProducerRecord<K, V> sign(ProducerRecord<K, V> record) {
        if (!properties.isSigningEnabled()) {
            return record;
        }

        byte[] payloadBytes = extractPayloadBytes(record.value());
        KmsClient.SignResultDto signResult = kmsClient.requestSignature(payloadBytes);

        Headers headers = record.headers();
        headers.remove(properties.getSignatureHeaderName());
        headers.remove(properties.getKeyIdHeaderName());

        headers.add(properties.getSignatureHeaderName(), signResult.signatureBase64().getBytes(StandardCharsets.UTF_8));
        headers.add(properties.getKeyIdHeaderName(), signResult.keyId().getBytes(StandardCharsets.UTF_8));

        return record;
    }

    public void signHeaders(Headers headers, byte[] payloadBytes) {
        if (!properties.isSigningEnabled()) {
            return;
        }

        KmsClient.SignResultDto signResult = kmsClient.requestSignature(payloadBytes);
        headers.remove(properties.getSignatureHeaderName());
        headers.remove(properties.getKeyIdHeaderName());

        headers.add(properties.getSignatureHeaderName(), signResult.signatureBase64().getBytes(StandardCharsets.UTF_8));
        headers.add(properties.getKeyIdHeaderName(), signResult.keyId().getBytes(StandardCharsets.UTF_8));
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
