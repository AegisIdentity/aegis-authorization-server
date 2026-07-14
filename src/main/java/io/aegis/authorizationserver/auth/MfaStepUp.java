package io.aegis.authorizationserver.auth;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

/**
 * The MFA step-up decision + pending-state machine, shared by the login success handler (which arms a
 * step-up), the gate filter (which blocks the authorization endpoint while a step-up is pending), and
 * the {@code /mfa} controller (which runs and clears it).
 *
 * <p>Decision after a correct password:
 * <ul>
 *   <li><b>Enrolled</b> in a factor → <b>CHALLENGE</b> (must present it). A registered factor is always
 *       enforced, regardless of the org toggle — the secure default.</li>
 *   <li>Org <b>requires MFA</b> but the user has no factor → <b>ENROL</b> (must set one up now).</li>
 *   <li>Otherwise → <b>NONE</b> (login proceeds).</li>
 * </ul>
 *
 * <p>The pending flag lives in the HTTP session. It is set here after the password factor and cleared
 * only once the second factor verifies, so an attacker holding just the password cannot reach the
 * authorization endpoint (the gate filter enforces this on {@code /oauth2/authorize}).
 */
@Component
public class MfaStepUp {

    public enum Mode { NONE, CHALLENGE, ENROL }

    static final String PENDING = "AEGIS_MFA_PENDING";
    static final String MODE = "AEGIS_MFA_MODE";
    static final String TENANT = "AEGIS_MFA_TENANT";
    static final String SUBJECT = "AEGIS_MFA_SUBJECT";
    static final String ACCOUNT = "AEGIS_MFA_ACCOUNT";
    static final String ENROL_SECRET = "AEGIS_MFA_ENROL_SECRET";
    static final String ENROL_URI = "AEGIS_MFA_ENROL_URI";

    private final MfaClient mfaClient;

    public MfaStepUp(MfaClient mfaClient) {
        this.mfaClient = mfaClient;
    }

    /**
     * Decide whether the just-password-authenticated user needs a step-up and, if so, arm the session.
     * Returns the mode; {@link Mode#NONE} means login may proceed normally.
     */
    public Mode arm(HttpServletRequest request, Authentication authentication) {
        if (!(authentication.getPrincipal() instanceof AegisUserPrincipal principal)) {
            return Mode.NONE;
        }
        boolean mfaRequired = authentication.getDetails() instanceof TenantWebAuthenticationDetails d
                && d.isMfaRequired();
        // The MFA subject MUST equal the token's `sub` claim — that is what the self-service MFA API keys
        // factors on (it reads caller.getSubject()). Spring Authorization Server derives `sub` from the
        // principal name, i.e. AegisUserPrincipal#getName() == username. Keying step-up on anything else
        // (e.g. the internal userId) would look up a different record and silently skip enforcement.
        String subject = principal.getName();
        boolean enrolled = mfaClient.status(principal.tenantId(), subject).enrolled();

        Mode mode = enrolled ? Mode.CHALLENGE : (mfaRequired ? Mode.ENROL : Mode.NONE);
        if (mode == Mode.NONE) {
            return Mode.NONE;
        }
        HttpSession session = request.getSession(true);
        session.setAttribute(PENDING, Boolean.TRUE);
        session.setAttribute(MODE, mode.name());
        session.setAttribute(TENANT, principal.tenantId());
        session.setAttribute(SUBJECT, subject);
        session.setAttribute(ACCOUNT, principal.username());
        return mode;
    }

    public boolean isPending(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        return session != null && Boolean.TRUE.equals(session.getAttribute(PENDING));
    }

    public Mode mode(HttpSession session) {
        Object m = session.getAttribute(MODE);
        return m == null ? Mode.NONE : Mode.valueOf(m.toString());
    }

    /** The tenant of the pending step-up (for branding the page). */
    public String tenant(HttpSession session) {
        return str(session, TENANT);
    }

    /**
     * For the ENROL mode: mint a TOTP secret once and cache the otpauth URI + secret in the session so a
     * page refresh doesn't rotate the secret out from under the user mid-enrolment.
     */
    public MfaClient.Enrollment ensureEnrolment(HttpSession session) {
        Object cachedSecret = session.getAttribute(ENROL_SECRET);
        Object cachedUri = session.getAttribute(ENROL_URI);
        if (cachedSecret != null && cachedUri != null) {
            return new MfaClient.Enrollment(cachedSecret.toString(), cachedUri.toString());
        }
        MfaClient.Enrollment enrolment = mfaClient.enrollTotp(
                str(session, TENANT), str(session, SUBJECT), str(session, ACCOUNT));
        session.setAttribute(ENROL_SECRET, enrolment.secret());
        session.setAttribute(ENROL_URI, enrolment.otpauthUri());
        return enrolment;
    }

    /** Verify the submitted code for the pending step-up. True completes it. */
    public boolean verify(HttpSession session, String code) {
        String tenant = str(session, TENANT);
        String subject = str(session, SUBJECT);
        return switch (mode(session)) {
            case CHALLENGE -> mfaClient.validateTotp(tenant, subject, code);
            case ENROL -> mfaClient.verifyEnableTotp(tenant, subject, code);
            case NONE -> false;
        };
    }

    /** Clear all step-up state — called once the second factor has verified. */
    public void clear(HttpSession session) {
        for (String key : new String[] {PENDING, MODE, TENANT, SUBJECT, ACCOUNT, ENROL_SECRET, ENROL_URI}) {
            session.removeAttribute(key);
        }
    }

    private static String str(HttpSession session, String key) {
        Object v = session.getAttribute(key);
        return v == null ? null : v.toString();
    }
}
