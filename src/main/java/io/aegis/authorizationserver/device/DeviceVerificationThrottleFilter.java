package io.aegis.authorizationserver.device;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.ConcurrentHashMap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.lang.NonNull;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Rate-limits submissions to the device-verification endpoint (RFC 8628 §3.3), where a signed-in
 * user enters the short {@code user_code} shown on a device.
 *
 * <p><b>The threat.</b> The {@code user_code} is short by design — a human types it — so it is
 * brute-forceable. The endpoint requires an authenticated session, so the attacker is an
 * authenticated user trying to guess a device authorization <em>pending for someone else</em> and
 * bind that stranger's device to their own approval. Spring expires and single-uses codes but does
 * not throttle guesses; this filter adds that control, mirroring the MFA service's
 * {@code TotpAttemptLimiter}.
 *
 * <p><b>Why a plain rate cap</b> rather than a failure-counting lockout: a legitimate user submits a
 * code once, maybe twice after a typo — never dozens of times. Capping attempts per authenticated
 * subject per rolling window therefore needs no inspection of whether each attempt succeeded, which
 * keeps the filter simple and its behaviour obvious. Over the cap returns 429.
 *
 * <p><b>Scope.</b> State is per-instance (in-memory). For a multi-replica deployment this moves to
 * Redis for a global cap — the same follow-up noted for {@code TotpAttemptLimiter} — but per-instance
 * still meaningfully bounds a single pod, and the edge rate limiter is the platform-wide backstop.
 */
public class DeviceVerificationThrottleFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(DeviceVerificationThrottleFilter.class);

    static final int MAX_ATTEMPTS = 10;
    static final Duration WINDOW = Duration.ofMinutes(1);

    private final String verificationEndpointUri;
    private final ConcurrentHashMap<String, Window> bySubject = new ConcurrentHashMap<>();

    public DeviceVerificationThrottleFilter(String verificationEndpointUri) {
        this.verificationEndpointUri = verificationEndpointUri;
    }

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request,
                                    @NonNull HttpServletResponse response,
                                    @NonNull FilterChain filterChain)
            throws ServletException, IOException {
        // Only the POST that submits a user_code — a GET renders the form and must not be throttled.
        boolean isSubmission = "POST".equals(request.getMethod())
                && verificationEndpointUri.equals(request.getRequestURI())
                && request.getParameter("user_code") != null;

        if (isSubmission && overLimit(subjectKey())) {
            log.warn("device-verification rate limit hit for subject={}", subjectKey());
            response.setStatus(429); // Too Many Requests
            response.setHeader("Retry-After", Long.toString(WINDOW.toSeconds()));
            response.getWriter().write("{\"error\":\"too_many_requests\"}");
            response.setContentType("application/json");
            return;
        }
        filterChain.doFilter(request, response);
    }

    /** True once the subject exceeds {@link #MAX_ATTEMPTS} within the rolling {@link #WINDOW}. */
    private boolean overLimit(String subject) {
        Instant now = Instant.now();
        Window window = bySubject.compute(subject, (ignored, existing) -> {
            if (existing == null || now.isAfter(existing.windowStart.plus(WINDOW))) {
                Window fresh = new Window();
                fresh.windowStart = now;
                fresh.count = 0;
                return fresh;
            }
            return existing;
        });
        return window.increment() > MAX_ATTEMPTS;
    }

    /**
     * The throttle key: the authenticated subject if there is one, else the client IP. The endpoint
     * is normally reached only when authenticated, but keying on IP for the anonymous case means an
     * unauthenticated flood is still bounded rather than unthrottled.
     */
    private static String subjectKey() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null && auth.isAuthenticated()
                && !"anonymousUser".equals(String.valueOf(auth.getPrincipal()))) {
            return "sub:" + auth.getName();
        }
        return "anon";
    }

    private static final class Window {
        private Instant windowStart;
        private int count;

        private synchronized int increment() {
            return ++count;
        }
    }
}
