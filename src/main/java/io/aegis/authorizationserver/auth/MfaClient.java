package io.aegis.authorizationserver.auth;

import java.util.List;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientResponseException;

/**
 * Calls {@code mfa-webauthn-service}'s server-to-server step-up API on behalf of the user being
 * authenticated, using the AS's own service JWT (which carries {@code mfa:verify}). Used by the login
 * flow to decide on and run an MFA step-up after the password factor succeeds.
 *
 * <p>Reads fail <em>closed for enrolment questions</em>: if the MFA service is unreachable we report
 * "not enrolled" so a missing dependency never silently drops a user's second factor — but a required
 * step-up whose validation can't be reached simply fails to verify (the user is re-prompted), never
 * bypassed.
 */
@Component
public class MfaClient {

    private static final Logger log = LoggerFactory.getLogger(MfaClient.class);

    private final ServiceTokenProvider serviceToken;
    private final RestClient restClient;

    public MfaClient(ServiceTokenProvider serviceToken,
                     @Value("${aegis.mfa-service.base-url:http://localhost:9103}") String baseUrl) {
        this.serviceToken = serviceToken;
        this.restClient = RestClient.builder().baseUrl(baseUrl).build();
    }

    /** Whether the user has an enabled second factor, and which methods. */
    public StepUpStatus status(String tenant, String subject) {
        try {
            StepUpStatus status = restClient.get()
                    .uri(uri -> uri.path("/api/v1/mfa/internal/status")
                            .queryParam("tenant", tenant).queryParam("subject", subject).build())
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + serviceToken.token())
                    .retrieve()
                    .body(StepUpStatus.class);
            return status == null ? new StepUpStatus(false, List.of()) : status;
        } catch (Exception ex) {
            log.warn("MFA status unreachable for tenant={} subject={}: {} — treating as not-enrolled",
                    tenant, subject, ex.toString());
            return new StepUpStatus(false, List.of());
        }
    }

    /** Validate a TOTP code for an already-enabled factor. False on any failure (re-prompt, never bypass). */
    public boolean validateTotp(String tenant, String subject, String code) {
        try {
            ValidateResponse result = restClient.post()
                    .uri("/api/v1/mfa/internal/totp/validate")
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + serviceToken.token())
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(Map.of("tenant", tenant, "subject", subject, "code", code))
                    .retrieve()
                    .body(ValidateResponse.class);
            return result != null && result.valid();
        } catch (Exception ex) {
            log.warn("MFA validate failed for tenant={} subject={}: {}", tenant, subject, ex.toString());
            return false;
        }
    }

    /** Force-enrol: mint a disabled TOTP secret for the user (first-time enrolment during login). */
    public Enrollment enrollTotp(String tenant, String subject, String account) {
        Enrollment e = restClient.post()
                .uri("/api/v1/mfa/internal/totp/enroll")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + serviceToken.token())
                .contentType(MediaType.APPLICATION_JSON)
                .body(Map.of("tenant", tenant, "subject", subject, "account", account))
                .retrieve()
                .body(Enrollment.class);
        if (e == null) {
            throw new IllegalStateException("MFA service returned no enrolment");
        }
        return e;
    }

    /** Confirm a force-enrolment with the first live code (activates the factor). True if the code was accepted. */
    public boolean verifyEnableTotp(String tenant, String subject, String code) {
        try {
            restClient.post()
                    .uri("/api/v1/mfa/internal/totp/verify-enable")
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + serviceToken.token())
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(Map.of("tenant", tenant, "subject", subject, "code", code))
                    .retrieve()
                    .toBodilessEntity();
            return true;
        } catch (RestClientResponseException ex) {
            // 400 = wrong code (expected on a mistyped confirmation); re-prompt.
            return false;
        } catch (Exception ex) {
            log.warn("MFA verify-enable failed for tenant={} subject={}: {}", tenant, subject, ex.toString());
            return false;
        }
    }

    public record StepUpStatus(boolean enrolled, List<String> methods) {
    }

    public record Enrollment(String secret, String otpauthUri) {
    }

    private record ValidateResponse(boolean valid) {
    }
}
