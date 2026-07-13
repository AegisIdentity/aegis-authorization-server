package io.aegis.authorizationserver.web;

import io.aegis.authorizationserver.federation.BrokerClient;
import io.aegis.authorizationserver.federation.BrokerClientRegistrationRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.net.URI;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

/**
 * Serves the branded login page. Also surfaces the tenant's "Sign in with …" providers: the tenant is
 * derived from the saved authorize request's per-tenant issuer path ({@code /{tenant}/oauth2/authorize}),
 * so a tenant's app that starts login at its own issuer gets that tenant's social/OIDC buttons. The
 * console (root issuer) has no tenant context here, so only password login is shown.
 */
@Controller
public class LoginController {

    private static final Pattern TENANT_PATH = Pattern.compile("^/([^/]+)/oauth2/authorize");

    private final BrokerClient broker;
    private final RequestCache requestCache = new HttpSessionRequestCache();

    public LoginController(BrokerClient broker) {
        this.broker = broker;
    }

    @GetMapping("/login")
    public String login(HttpServletRequest request, HttpServletResponse response, Model model) {
        String tenant = tenantFromSavedRequest(request, response);
        if (tenant != null) {
            List<ProviderButton> providers = broker.listEnabled(tenant).stream()
                    .map(p -> new ProviderButton(
                            p.displayName(),
                            p.providerKey(),
                            "/oauth2/authorization/" + BrokerClientRegistrationRepository.registrationId(tenant, p.alias())))
                    .toList();
            model.addAttribute("providers", providers);
        }
        return "login";
    }

    private String tenantFromSavedRequest(HttpServletRequest request, HttpServletResponse response) {
        SavedRequest saved = requestCache.getRequest(request, response);
        if (saved == null) {
            return null;
        }
        try {
            String path = URI.create(saved.getRedirectUrl()).getPath();
            Matcher m = TENANT_PATH.matcher(path);
            return m.find() ? m.group(1) : null;
        } catch (Exception ex) {
            return null;
        }
    }

    /** View model for a "Sign in with X" button. */
    public record ProviderButton(String label, String providerKey, String url) {
    }
}
