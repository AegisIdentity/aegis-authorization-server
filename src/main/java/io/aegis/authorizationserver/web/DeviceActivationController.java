package io.aegis.authorizationserver.web;

import io.aegis.authorizationserver.auth.AegisUserPrincipal;
import io.aegis.authorizationserver.branding.BrandingClient;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

/**
 * The second-screen page of the Device Authorization Grant (RFC 8628).
 *
 * <p>A device that cannot host a browser (TV, CLI, IoT) displays a short {@code user_code} and this
 * page's URL. The user opens it on a phone or laptop, signs in normally, and submits the code; the
 * form POSTs to the Authorization Server's device-verification endpoint, which matches the code to
 * the pending device authorization and runs consent.
 *
 * <p>The page sits behind {@code anyRequest().authenticated()} (see {@code DefaultSecurityConfig}),
 * so an unauthenticated visitor is sent to {@code /login} and returns here afterwards. That ordering
 * is load-bearing: the entire grant rests on a <em>human who has proven who they are</em> approving
 * the code, because the device itself is a public client that cannot authenticate.
 *
 * <p>When the device encodes the code into the URL it renders as a QR
 * ({@code verification_uri_complete}), it arrives as {@code ?user_code=...} and is pre-filled. The
 * user must still submit, so following a link alone never authorizes anything.
 */
@Controller
public class DeviceActivationController {

    private final BrandingClient branding;

    public DeviceActivationController(BrandingClient branding) {
        this.branding = branding;
    }

    @GetMapping("/activate")
    public String activate(@RequestParam(value = "user_code", required = false) String userCode,
                           Authentication authentication,
                           Model model) {
        String tenant = tenantOf(authentication);
        model.addAttribute("brand", branding.forTenant(tenant));
        model.addAttribute("brandTenant", tenant == null ? "" : tenant);
        // Pre-fill only; approval still requires an explicit submit by the signed-in user.
        model.addAttribute("userCode", userCode == null ? "" : userCode);
        return "activate";
    }

    /** The signed-in user's tenant, so the page carries their organization's branding. */
    private static String tenantOf(Authentication authentication) {
        if (authentication != null && authentication.getPrincipal() instanceof AegisUserPrincipal principal) {
            return principal.tenantId();
        }
        return null;
    }
}
