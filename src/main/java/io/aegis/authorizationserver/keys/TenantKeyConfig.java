package io.aegis.authorizationserver.keys;

import io.aegis.authorizationserver.auth.TenantJwkSource;
import io.aegis.commons.crypto.FieldEncryption;
import java.util.Arrays;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.util.StringUtils;

/**
 * Wires durable, encrypted-at-rest tenant signing keys.
 *
 * <p>Key-material protection follows the same fail-closed rule the MFA and social-broker services
 * already use: a real key from {@code aegis.crypto.field-key} (env {@code AEGIS_FIELD_ENC_KEY}) is
 * required in every deployment, and the only exception is an <em>explicitly</em> active {@code dev}
 * profile, which supplies a well-known throwaway key so a local run works out of the box. A deploy
 * that forgets the profile and the key fails to start rather than silently protecting production
 * signing keys with a value published in source control.
 */
@Configuration(proxyBeanMethods = false)
public class TenantKeyConfig {

    private static final Logger log = LoggerFactory.getLogger(TenantKeyConfig.class);

    /**
     * Fixed dev key (32 bytes, base64) — identical to the one the MFA service uses so a developer
     * has one value to remember. NOT a secret; must never protect real data.
     */
    private static final String DEV_KEY_B64 = "YWVnaXMtZGV2LWZpZWxkLWVuY3J5cHRpb24ta2V5MzI=";

    /** AES-256 key protecting tenant private-key material at rest. */
    @Bean
    public FieldEncryption tenantKeyEncryption(Environment env,
                                               @Value("${aegis.crypto.field-key:}") String configuredKey) {
        if (StringUtils.hasText(configuredKey)) {
            return FieldEncryption.fromBase64Key(configuredKey);
        }
        if (devProfileActive(env)) {
            log.warn("Using the built-in DEV field-encryption key — tenant signing keys are NOT "
                    + "protected by a real secret. Only allowed under the explicit 'dev' profile.");
            return FieldEncryption.fromBase64Key(DEV_KEY_B64);
        }
        throw new IllegalStateException(
                "aegis.crypto.field-key (AEGIS_FIELD_ENC_KEY) must be set — tenant signing keys are "
                        + "encrypted at rest. Refusing to start with the built-in dev key outside the "
                        + "explicit 'dev' profile.");
    }

    /**
     * Durable key storage. Keys must be shared across replicas and survive restarts, so the JPA store
     * is the only correct choice for a deployed service; the in-memory store exists solely for unit
     * tests and is never selected here.
     */
    @Bean
    public TenantKeyStore tenantKeyStore(TenantSigningKeyRepository repository,
                                         FieldEncryption tenantKeyEncryption) {
        return new JpaTenantKeyStore(repository, tenantKeyEncryption);
    }

    @Bean
    public TenantJwkSource tenantJwkSource(TenantKeyStore tenantKeyStore) {
        return new TenantJwkSource(tenantKeyStore);
    }

    /** Mirrors {@code @Profile("dev")} — the dev key is opt-in, never a silent fallback. */
    private static boolean devProfileActive(Environment env) {
        return Arrays.stream(env.getActiveProfiles()).anyMatch(p -> p.equalsIgnoreCase("dev"));
    }
}
