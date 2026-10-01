package com.afromane.security.kafka.signer;

import com.afromane.security.kafka.ZeroTrustKafkaProperties;
import com.afromane.security.kafka.client.KmsClient;
import org.apache.kafka.clients.producer.ProducerRecord;
import org.apache.kafka.common.header.Headers;

import java.nio.charset.StandardCharsets;

/**
 * Composant injecté dans les producteurs Kafka pour signer numériquement les événements émis.
 * <p>
 * Ce service extrait le payload du {@link ProducerRecord}, sollicite la signature RSA auprès du KMS
 * et injecte les en-têtes Kafka :
 * <ul>
 *   <li>{@code X-Signature-RSA} : signature numérique en Base64</li>
 *   <li>{@code X-Key-Id} : identifiant de la clé utilisée pour permettre la sélection de la bonne clé publique par le récepteur</li>
 * </ul>
 * </p>
 *
 * @author afromane
 * @version 1.0.0
 */
public class KafkaMessageSigner {

    private final KmsClient kmsClient;
    private final ZeroTrustKafkaProperties properties;

    /**
     * Construit le signataire de messages avec le client KMS et la configuration Kafka.
     *
     * @param kmsClient  client communiquant avec le KMS
     * @param properties configuration de la signature
     */
    public KafkaMessageSigner(KmsClient kmsClient, ZeroTrustKafkaProperties properties) {
        this.kmsClient = kmsClient;
        this.properties = properties;
    }

    /**
     * Signe le contenu d'un {@link ProducerRecord} et injecte la signature et le keyId dans ses en-têtes.
     *
     * @param <K>    type de la clé du message
     * @param <V>    type de la valeur du message
     * @param record enregistrement Kafka à signer
     * @return le même enregistrement enrichi des en-têtes cryptographiques
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

    /**
     * Signe directement un tableau d'octets et applique les en-têtes sur l'objet {@link Headers} fourni.
     *
     * @param headers      en-têtes Kafka à enrichir
     * @param payloadBytes octets du payload à signer
     */
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

    /**
     * Convertit la valeur de l'événement en tableau d'octets de manière sûre.
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
