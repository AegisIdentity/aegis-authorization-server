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

    /**
     * Where the AES-256 data key that protects tenant signing keys comes from. Precedence:
     * <ol>
     *   <li><b>KMS envelope</b> ({@code aegis.crypto.kms.enabled=true}) — the data key is stored
     *       wrapped by a cloud KMS CMK and unwrapped at startup (ADR-0007). The strongest posture;
     *       the CMK never leaves KMS.</li>
     *   <li><b>Static key</b> ({@code aegis.crypto.field-key} set) — a base64 key from a secret
     *       manager. A legitimate interim posture (the KEK lives in a secret store, not a KMS).</li>
     *   <li><b>Dev key</b> — only under the explicit {@code dev} profile; a well-known throwaway key.</li>
     * </ol>
     * Outside dev with neither KMS nor a static key configured, startup fails — fail-closed, so
     * production never protects signing keys with the source-controlled dev value.
     */
    @Bean
    public io.aegis.authorizationserver.keys.kms.DataKeyProvider dataKeyProvider(
            Environment env,
            @Value("${aegis.crypto.field-key:}") String configuredKey,
            @Value("${aegis.crypto.kms.enabled:false}") boolean kmsEnabled,
            @Value("${aegis.crypto.kms.wrapped-data-key:}") String wrappedDataKey,
            org.springframework.beans.factory.ObjectProvider<
                    io.aegis.authorizationserver.keys.kms.KmsKeyUnwrapper> unwrapper) {
        if (kmsEnabled) {
            if (!StringUtils.hasText(wrappedDataKey)) {
                throw new IllegalStateException(
                        "aegis.crypto.kms.enabled=true requires aegis.crypto.kms.wrapped-data-key "
                                + "(the KMS-wrapped data key blob, base64)");
            }
            io.aegis.authorizationserver.keys.kms.KmsKeyUnwrapper u = unwrapper.getIfAvailable();
            if (u == null) {
                throw new IllegalStateException(
                        "aegis.crypto.kms.enabled=true but no KMS unwrapper is configured (check "
                                + "aegis.crypto.kms.key-id / region)");
            }
            log.info("Tenant key encryption: KMS envelope (data key unwrapped from the CMK).");
            return new io.aegis.authorizationserver.keys.kms.KmsEnvelopeDataKeyProvider(wrappedDataKey, u);
        }
        if (StringUtils.hasText(configuredKey)) {
            return new io.aegis.authorizationserver.keys.kms.StaticDataKeyProvider(configuredKey);
        }
        if (devProfileActive(env)) {
            log.warn("Using the built-in DEV field-encryption key — tenant signing keys are NOT "
                    + "protected by a real secret. Only allowed under the explicit 'dev' profile.");
            return new io.aegis.authorizationserver.keys.kms.StaticDataKeyProvider(DEV_KEY_B64);
        }
        throw new IllegalStateException(
                "no tenant-key protection configured — set aegis.crypto.kms.enabled=true (+ wrapped "
                        + "data key) or aegis.crypto.field-key (AEGIS_FIELD_ENC_KEY). Refusing to start "
                        + "with the built-in dev key outside the explicit 'dev' profile.");
    }

    /** AES-256 field encryption, keyed by the resolved data key (static or KMS-unwrapped). */
    @Bean
    public FieldEncryption tenantKeyEncryption(
            io.aegis.authorizationserver.keys.kms.DataKeyProvider dataKeyProvider) {
        byte[] key = dataKeyProvider.resolveDataKey();
        try {
            return new FieldEncryption(key);
        } finally {
            java.util.Arrays.fill(key, (byte) 0); // don't leave the plaintext data key on the heap
        }
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
