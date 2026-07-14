package io.aegis.authorizationserver.web;

import io.aegis.authorizationserver.auth.MfaClient;
import io.aegis.authorizationserver.auth.MfaStepUp;
import io.aegis.authorizationserver.branding.BrandingClient;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

/**
 * The MFA step-up page, reached after a correct password when a second factor is required. It runs the
 * challenge (validate a code) or a first-time enrolment (show a secret, confirm a code), then — on
 * success — clears the pending flag and resumes the saved {@code /oauth2/authorize} request so the OAuth
 * flow continues and tokens are finally issued. It never issues tokens itself.
 */
@Controller
public class MfaController {

    private final MfaStepUp stepUp;
    private final BrandingClient branding;
    private final RequestCache requestCache = new HttpSessionRequestCache();

    public MfaController(MfaStepUp stepUp, BrandingClient branding) {
        this.stepUp = stepUp;
        this.branding = branding;
    }

    @GetMapping("/mfa")
    public String page(HttpServletRequest request, @RequestParam(required = false) String error, Model model) {
        HttpSession session = request.getSession(false);
        if (session == null || !stepUp.isPending(request)) {
            // Nothing pending — don't expose the page; send the user back to start.
            return "redirect:/login";
        }
        MfaStepUp.Mode mode = stepUp.mode(session);
        model.addAttribute("mode", mode.name());
        model.addAttribute("error", error != null);
        if (mode == MfaStepUp.Mode.ENROL) {
            MfaClient.Enrollment enrolment = stepUp.ensureEnrolment(session);
            model.addAttribute("secret", enrolment.secret());
            model.addAttribute("otpauthUri", enrolment.otpauthUri());
        }
        String tenant = stepUp.tenant(session);
        model.addAttribute("brand", branding.forTenant(tenant));
        model.addAttribute("brandTenant", tenant == null ? "" : tenant);
        return "mfa";
    }

    @PostMapping("/mfa")
    public String verify(HttpServletRequest request, HttpServletResponse response,
                         @RequestParam String code) {
        HttpSession session = request.getSession(false);
        if (session == null || !stepUp.isPending(request)) {
            return "redirect:/login";
        }
        if (!stepUp.verify(session, code.trim())) {
            return "redirect:/mfa?error";
        }
        // Second factor verified: drop the gate and resume the original authorize request.
        stepUp.clear(session);
        SavedRequest saved = requestCache.getRequest(request, response);
        if (saved != null) {
            return "redirect:" + saved.getRedirectUrl();
        }
        return "redirect:/";
    }
}
