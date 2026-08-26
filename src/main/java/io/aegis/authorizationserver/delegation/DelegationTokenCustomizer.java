package io.aegis.authorizationserver.delegation;

import io.aegis.commons.audit.AuditEvent;
import io.aegis.commons.audit.AuditEventPublisher;
import io.aegis.commons.audit.AuditOutcome;
import io.aegis.commons.audit.DelegationChain;
import io.aegis.commons.audit.DelegationHop;
import io.aegis.commons.audit.PrincipalType;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenExchangeActor;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenExchangeCompositeAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;

/**
 * Applies delegation semantics to tokens minted by RFC 8693 token exchange (ADR-0012).
 *
 * <p>Three jobs, in order:
 * <ol>
 *   <li>set {@code sub} to the <b>root</b> subject and nest the actor chain into {@code act}, so the
 *       accountable human is always one claim away no matter how deep delegation went;</li>
 *   <li>refuse any exchange that <b>widens</b> scope — the delegation-laundering defence;</li>
 *   <li>emit an audit event carrying the full delegation chain.</li>
 * </ol>
 *
 * <p>Non-exchange grants pass through untouched: this class only has an opinion about delegation.
 *
 * <p><b>On enforcing narrowing here.</b> A token customizer is a slightly unusual place for an
 * authorization check, and it is chosen deliberately: it is the last point at which every input is
 * available together (subject-token scopes, requested scopes, the resolved actor chain) and throwing
 * still prevents issuance. Placing it earlier would mean re-deriving the actor chain in a second
 * location, and two derivations that can disagree is precisely the failure ADR-0010 warns about.
 */
public class DelegationTokenCustomizer implements OAuth2TokenCustomizer<JwtEncodingContext> {

    /** Context attribute holding the scopes carried by the subject token being exchanged. */
    public static final String SUBJECT_SCOPES_ATTRIBUTE = "aegis.subject-token.scopes";

    private final AuditEventPublisher audit;

    public DelegationTokenCustomizer(AuditEventPublisher audit) {
        this.audit = audit;
    }

    @Override
    public void customize(JwtEncodingContext context) {
        Object principal = context.getPrincipal();
        if (!(principal instanceof OAuth2TokenExchangeCompositeAuthenticationToken exchange)) {
            return; // not a delegation; leave client_credentials / authorization_code alone
        }

        DelegationChain chain = chainOf(exchange, context.getAuthorizedScopes());
        Set<String> subjectScopes = subjectScopes(context);
        ScopeNarrowing.Result narrowing =
                ScopeNarrowing.check(subjectScopes, context.getAuthorizedScopes());

        if (!narrowing.permitted()) {
            record(chain, AuditOutcome.DENIED, String.join(" ", narrowing.escalated()));
            throw new OAuth2AuthenticationException(new OAuth2Error(
                    OAuth2ErrorCodes.INVALID_SCOPE,
                    "token exchange may not widen authority; escalated scopes: "
                            + String.join(" ", narrowing.escalated()),
                    null));
        }

        String subject = DelegationClaims.subjectOf(chain);
        if (subject != null) {
            context.getClaims().subject(subject);
        }
        Map<String, Object> act = DelegationClaims.toActClaim(chain);
        if (act != null) {
            context.getClaims().claim("act", act);
        }
        record(chain, AuditOutcome.SUCCESS, null);
    }

    /**
     * Build a root-first chain from SAS's composite token.
     *
     * <p>SAS supplies actors <b>nearest-first</b>, mirroring the {@code act}-claim nesting they were
     * parsed from, so the list is reversed here to produce Aegis's root-first ordering. Getting this
     * backwards would attribute actions to the wrong principal — worse than having no chain at all —
     * which is why the ordering is asserted by test rather than assumed.
     */
    private static DelegationChain chainOf(OAuth2TokenExchangeCompositeAuthenticationToken exchange,
                                           Set<String> scopes) {
        List<DelegationHop> hops = new ArrayList<>();
        Object subject = exchange.getSubject() == null ? null : exchange.getSubject().getPrincipal();
        if (subject != null) {
            hops.add(new DelegationHop(String.valueOf(subject), PrincipalType.HUMAN, null,
                    Instant.now(), scopes == null ? Set.of() : scopes));
        }
        List<OAuth2TokenExchangeActor> actors = new ArrayList<>(exchange.getActors());
        for (int i = actors.size() - 1; i >= 0; i--) {
            String actorSubject = actors.get(i).getSubject();
            if (actorSubject != null && !actorSubject.isBlank()) {
                hops.add(new DelegationHop(actorSubject, PrincipalType.AGENT, null, Instant.now(),
                        scopes == null ? Set.of() : scopes));
            }
        }
        return new DelegationChain(hops);
    }

    @SuppressWarnings("unchecked")
    private static Set<String> subjectScopes(JwtEncodingContext context) {
        Object attribute = context.get(SUBJECT_SCOPES_ATTRIBUTE);
        return attribute instanceof Set<?> set ? new LinkedHashSet<>((Set<String>) set) : null;
    }

    private void record(DelegationChain chain, AuditOutcome outcome, String escalatedScopes) {
        if (audit == null) {
            return;
        }
        AuditEvent.Builder event = AuditEvent.of("authz", "token.exchange", outcome)
                .delegation(chain);
        if (escalatedScopes != null) {
            event.attribute("escalatedScopes", escalatedScopes);
        }
        audit.publish(event.build());
    }
}
