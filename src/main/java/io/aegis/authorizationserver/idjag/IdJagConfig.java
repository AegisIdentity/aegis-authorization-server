package io.aegis.authorizationserver.idjag;

import io.aegis.commons.audit.AuditEventPublisher;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.Set;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;

/**
 * Wires the RFC 7523 {@code jwt-bearer} grant used to redeem an ID-JAG (ADR-0012).
 *
 * <p>Gated on {@code aegis.idjag.enabled}, and the reason is the issuer allow-list. Accepting grants
 * from <em>any</em> issuer whose signing key we happen to be able to fetch would be a serious hole,
 * so the grant stays off until an operator has said explicitly which IdPs may mint assertions for
 * this server's resources.
 */
@Configuration(proxyBeanMethods = false)
@ConditionalOnProperty(prefix = "aegis.idjag", name = "enabled", havingValue = "true")
public class IdJagConfig {

    @Bean
    public IdJagAssertionValidator idJagAssertionValidator(
            @Value("${aegis.idjag.trusted-issuers:}") String trustedIssuers) {
        Set<String> issuers = new LinkedHashSet<>();
        if (trustedIssuers != null && !trustedIssuers.isBlank()) {
            Arrays.stream(trustedIssuers.split(","))
                    .map(String::trim)
                    .filter(issuer -> !issuer.isEmpty())
                    .forEach(issuers::add);
        }
        return new IdJagAssertionValidator(issuers);
    }

    @Bean
    public IdJagAuthenticationProvider idJagAuthenticationProvider(
            JwtDecoder jwtDecoder,
            IdJagAssertionValidator validator,
            OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator,
            OAuth2AuthorizationService authorizationService,
            ObjectProvider<AuditEventPublisher> audit) {
        return new IdJagAuthenticationProvider(jwtDecoder, validator, tokenGenerator,
                authorizationService, audit.getIfAvailable(() -> event -> { }));
    }
}
