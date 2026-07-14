package io.aegis.authorizationserver.tenantapp;

import io.aegis.authorizationserver.federation.BrokerClient;
import java.util.List;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoders;
import org.springframework.security.oauth2.jwt.JwtTimestampValidator;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.stereotype.Component;

/**
 * Verifies a provider-issued OIDC id_token that a tenant's native app obtained from a native SDK
 * ("Sign in with Google/Apple") and wants to exchange for Aegis tokens. Validates the signature against
 * the provider's JWKS, the issuer, the audience (must be the provider client_id the tenant registered),
 * and expiry — then extracts a <b>verified</b> email.
 *
 * <p>Account-takeover guard (same rule as browser federation): the email is only trusted when the
 * provider asserts {@code email_verified == true}. An unverified email is refused, so a native token
 * can never be used to link into someone else's account by claiming their address.
 */
@Component
public class NativeProviderVerifier {

    public static class NativeVerificationException extends RuntimeException {
        public NativeVerificationException(String message) {
            super(message);
        }
    }

    public record VerifiedIdentity(String email, String preferredUsername) {
    }

    public VerifiedIdentity verify(BrokerClient.ProviderConfig provider, String idToken) {
        if (provider == null) {
            throw new NativeVerificationException("unknown provider");
        }
        // Fail closed: without a configured client id there is no audience to validate the id_token
        // against, so a token minted for any app would otherwise be accepted. Refuse up front.
        if (provider.clientId() == null || provider.clientId().isBlank()) {
            throw new NativeVerificationException(
                    "provider is not configured with a client id; id_token audience cannot be validated");
        }
        Jwt jwt;
        try {
            jwt = decoderFor(provider).decode(idToken);
        } catch (Exception ex) {
            throw new NativeVerificationException("id_token verification failed: " + ex.getMessage());
        }
        // Audience MUST equal the provider client_id the tenant configured — this is what stops an
        // id_token minted for a *different* app from being replayed here to impersonate its subject.
        List<String> aud = jwt.getAudience();
        if (aud == null || !aud.contains(provider.clientId())) {
            throw new NativeVerificationException("id_token audience does not match the configured provider client");
        }
        // OIDC Core 3.1.3.7: when the id_token has more than one audience, the authorized party (azp)
        // MUST be present and MUST be our client id.
        if (aud.size() > 1) {
            String azp = jwt.getClaimAsString("azp");
            if (azp == null || !azp.equals(provider.clientId())) {
                throw new NativeVerificationException("id_token azp does not match the configured provider client");
            }
        }
        Object verified = jwt.getClaim("email_verified");
        String email = jwt.getClaimAsString("email");
        if (!isTrue(verified) || email == null || email.isBlank()) {
            throw new NativeVerificationException("provider did not assert a verified email");
        }
        String preferred = jwt.getClaimAsString("preferred_username");
        return new VerifiedIdentity(email.toLowerCase(java.util.Locale.ROOT),
                preferred != null ? preferred : email.toLowerCase(java.util.Locale.ROOT));
    }

    private JwtDecoder decoderFor(BrokerClient.ProviderConfig provider) {
        // Prefer explicit JWKS; otherwise discover from the issuer (OIDC providers).
        if (provider.jwkSetUri() != null && !provider.jwkSetUri().isBlank()) {
            NimbusJwtDecoder decoder = NimbusJwtDecoder.withJwkSetUri(provider.jwkSetUri()).build();
            decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(
                    new JwtTimestampValidator(), issuerValidator(provider.issuerUri())));
            return decoder;
        }
        if (provider.issuerUri() != null && !provider.issuerUri().isBlank()) {
            return JwtDecoders.fromIssuerLocation(provider.issuerUri());
        }
        throw new NativeVerificationException("provider has no jwks/issuer for native token verification");
    }

    private static OAuth2TokenValidator<Jwt> issuerValidator(String expectedIssuer) {
        return jwt -> {
            if (expectedIssuer == null || expectedIssuer.isBlank()) {
                return OAuth2TokenValidatorResult.success();
            }
            String iss = jwt.getIssuer() == null ? null : jwt.getIssuer().toString();
            return expectedIssuer.equals(iss)
                    ? OAuth2TokenValidatorResult.success()
                    : OAuth2TokenValidatorResult.failure(new OAuth2Error("invalid_token", "unexpected issuer: " + iss, null));
        };
    }

    private static boolean isTrue(Object claim) {
        return Boolean.TRUE.equals(claim) || "true".equalsIgnoreCase(String.valueOf(claim));
    }
}
