package io.aegis.authorizationserver.keys.kms;

import java.net.URI;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.util.StringUtils;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.kms.KmsClient;

/**
 * Wires the AWS KMS client and unwrapper — only when {@code aegis.crypto.kms.enabled=true}. When KMS
 * is off (local dev, unit tests, or a deployment that keeps its key in a secret manager) none of
 * these beans exist and the tenant-key encryption falls back to a static data key.
 *
 * <p>In production, region comes from config and credentials from the default provider chain (IRSA
 * on EKS). The optional {@code endpoint} and static-credential properties exist so a LocalStack
 * container can stand in for real KMS in tests — the same SDK code path, no cloud account.
 */
@Configuration(proxyBeanMethods = false)
@ConditionalOnProperty(name = "aegis.crypto.kms.enabled", havingValue = "true")
public class KmsConfig {

    @Bean(destroyMethod = "close")
    public KmsClient kmsClient(
            @Value("${aegis.crypto.kms.region:us-east-1}") String region,
            @Value("${aegis.crypto.kms.endpoint:}") String endpoint,
            @Value("${aegis.crypto.kms.access-key:}") String accessKey,
            @Value("${aegis.crypto.kms.secret-key:}") String secretKey) {
        var builder = KmsClient.builder().region(Region.of(region));
        if (StringUtils.hasText(endpoint)) {
            builder.endpointOverride(URI.create(endpoint)); // LocalStack / VPC endpoint
        }
        if (StringUtils.hasText(accessKey)) {
            // Explicit credentials — used for LocalStack. Production leaves these unset and uses the
            // default provider chain (IRSA), which is the least-privilege, no-static-secret path.
            builder.credentialsProvider(StaticCredentialsProvider.create(
                    AwsBasicCredentials.create(accessKey, secretKey)));
        }
        return builder.build();
    }

    @Bean
    public KmsKeyUnwrapper kmsKeyUnwrapper(KmsClient kmsClient,
                                           @Value("${aegis.crypto.kms.key-id}") String keyId) {
        return new AwsKmsKeyUnwrapper(kmsClient, keyId);
    }
}
