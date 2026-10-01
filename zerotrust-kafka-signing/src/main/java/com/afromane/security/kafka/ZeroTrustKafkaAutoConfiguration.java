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

@AutoConfiguration
@ConditionalOnClass(KafkaTemplate.class)
@EnableConfigurationProperties(ZeroTrustKafkaProperties.class)
@ConditionalOnProperty(prefix = "zerotrust.kafka", name = "enabled", havingValue = "true", matchIfMissing = true)
public class ZeroTrustKafkaAutoConfiguration {

    private final ZeroTrustKafkaProperties properties;

    public ZeroTrustKafkaAutoConfiguration(ZeroTrustKafkaProperties properties) {
        this.properties = properties;
    }

    @Bean
    @ConditionalOnMissingBean
    public KmsClient kmsClient() {
        return new KmsClient(properties);
    }

    @Bean
    @ConditionalOnMissingBean
    public KafkaMessageSigner kafkaMessageSigner(KmsClient kmsClient) {
        return new KafkaMessageSigner(kmsClient, properties);
    }

    @Bean
    @ConditionalOnMissingBean
    public RecordInterceptor<Object, Object> kafkaSignatureRecordInterceptor(KmsClient kmsClient) {
        return new KafkaSignatureVerificationInterceptor<>(kmsClient, properties);
    }

    @Bean
    @ConditionalOnMissingBean(name = "zeroTrustKafkaContainerCustomizer")
    public ContainerCustomizer<Object, Object, ConcurrentMessageListenerContainer<Object, Object>> zeroTrustKafkaContainerCustomizer(
            RecordInterceptor<Object, Object> interceptor) {
        return container -> container.setRecordInterceptor(interceptor);
    }
}
