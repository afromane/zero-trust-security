package com.afromane.security.kafka;

import com.afromane.security.kafka.client.KmsClient;
import com.afromane.security.kafka.interceptor.KafkaSignatureVerificationInterceptor;
import com.afromane.security.kafka.signer.KafkaMessageSigner;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.kafka.config.ContainerCustomizer;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.kafka.listener.ConcurrentMessageListenerContainer;
import org.springframework.kafka.listener.RecordInterceptor;

/**
 * Classe d'auto-configuration Spring Boot pour la sécurité et la signature Kafka Zero Trust.
 * <p>
 * Déclare automatiquement :
 * <ul>
 *   <li>Le client {@link KmsClient} pour interagir avec le serveur de clés.</li>
 *   <li>Le bean {@link KafkaMessageSigner} pour signer les messages publiés par les producteurs.</li>
 *   <li>L'intercepteur {@link KafkaSignatureVerificationInterceptor} pour contrôler l'intégrité des messages reçus.</li>
 *   <li>Le {@link ContainerCustomizer} appliquant automatiquement l'intercepteur à tous les conteneurs d'écoute Kafka.</li>
 * </ul>
 * </p>
 *
 * @author afromane
 * @version 1.0.0
 */
@AutoConfiguration
@ConditionalOnClass(KafkaTemplate.class)
@EnableConfigurationProperties(ZeroTrustKafkaProperties.class)
@ConditionalOnProperty(prefix = "zerotrust.kafka", name = "enabled", havingValue = "true", matchIfMissing = true)
public class ZeroTrustKafkaAutoConfiguration {

    private final ZeroTrustKafkaProperties properties;

    /**
     * Initialise la classe d'auto-configuration avec les propriétés injectées.
     *
     * @param properties configuration de la sécurité Kafka
     */
    public ZeroTrustKafkaAutoConfiguration(ZeroTrustKafkaProperties properties) {
        this.properties = properties;
    }

    /**
     * Fournit le client communiquant avec le microservice KMS.
     *
     * @return instance de {@link KmsClient}
     */
    @Bean
    @ConditionalOnMissingBean
    public KmsClient kmsClient() {
        return new KmsClient(properties);
    }

    /**
     * Fournit le composant de signature des messages Kafka sortants.
     *
     * @param kmsClient client KMS
     * @return instance de {@link KafkaMessageSigner}
     */
    @Bean
    @ConditionalOnMissingBean
    public KafkaMessageSigner kafkaMessageSigner(KmsClient kmsClient) {
        return new KafkaMessageSigner(kmsClient, properties);
    }

    /**
     * Fournit l'intercepteur de vérification des signatures RSA pour les messages Kafka entrants.
     *
     * @param kmsClient client KMS
     * @return instance de {@link RecordInterceptor}
     */
    @Bean
    @ConditionalOnMissingBean
    public RecordInterceptor<Object, Object> kafkaSignatureRecordInterceptor(KmsClient kmsClient) {
        return new KafkaSignatureVerificationInterceptor<>(kmsClient, properties);
    }

    /**
     * Personnalise et configure automatiquement tous les conteneurs d'écoute {@code @KafkaListener}
     * en leur associant l'intercepteur de vérification de signature.
     *
     * @param interceptor intercepteur de vérification RSA
     * @return customizer de conteneurs de messages
     */
    @Bean
    @ConditionalOnMissingBean(name = "zeroTrustKafkaContainerCustomizer")
    public ContainerCustomizer<Object, Object, ConcurrentMessageListenerContainer<Object, Object>> zeroTrustKafkaContainerCustomizer(
            RecordInterceptor<Object, Object> interceptor) {
        return container -> container.setRecordInterceptor(interceptor);
    }
}
