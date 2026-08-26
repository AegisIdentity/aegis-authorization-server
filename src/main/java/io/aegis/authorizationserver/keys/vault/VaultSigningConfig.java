package io.aegis.authorizationserver.keys.vault;

import io.aegis.commons.vault.VaultTransit;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.security.oauth2.jwt.JwtEncoder;

/**
 * Switches token signing onto Vault Transit (ADR-0015, migration per {@code VAULT-ARCHITECTURE.md}
 * §7).
 *
 * <p>Behind a property, and that is the migration mechanism rather than timidity. §7 is
 * rotation-based: the new Vault {@code kid} must be published in JWKS <em>before</em> it signs
 * anything, and the old KMS {@code kid} must stay verifiable until every token it signed has
 * expired. A flag is what makes those two steps separable and reversible — flipping it back is a
 * safe rollback at any point before the old key is destroyed.
 *
 * <p>When enabled this {@link JwtEncoder} is {@code @Primary}, so Spring Authorization Server's token
 * generator picks it up in place of the {@code NimbusJwtEncoder} without any other wiring changing.
 */
@Configuration(proxyBeanMethods = false)
@ConditionalOnProperty(prefix = "aegis.vault.signing", name = "enabled", havingValue = "true")
public class VaultSigningConfig {

    @Bean
    public VaultTenantSigner vaultTenantSigner(
            VaultTransit transit,
            @org.springframework.beans.factory.annotation.Value(
                    "${aegis.vault.transit.token-signing-key:token-signing}") String keyPurpose) {
        return new VaultTenantSigner(transit, keyPurpose);
    }

    @Bean
    @Primary
    public JwtEncoder vaultJwtEncoder(VaultTenantSigner signer) {
        return new VaultJwtEncoder(signer);
    }
}
