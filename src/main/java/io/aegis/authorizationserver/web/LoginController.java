package io.aegis.authorizationserver.web;

import io.aegis.authorizationserver.branding.BrandingClient;
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
    private final BrandingClient branding;
    private final RequestCache requestCache = new HttpSessionRequestCache();

    public LoginController(BrokerClient broker, BrandingClient branding) {
        this.broker = broker;
        this.branding = branding;
    }

    @GetMapping("/login")
    public String login(HttpServletRequest request, HttpServletResponse response, Model model) {
        SavedRequest saved = requestCache.getRequest(request, response);
        String tenant = tenantFromSavedRequest(saved);
        if (tenant != null) {
            var enabled = broker.listEnabled(tenant);
            // idp_hint / connection: deep-link straight to one provider, skipping the chooser — so a
            // tenant app's native "Continue with Google" lands directly on the provider. Add
            // ?idp_hint=<alias|providerKey> to the /oauth2/authorize request.
            String hint = firstParam(saved, "idp_hint");
            if (hint == null) {
                hint = firstParam(saved, "connection");
            }
            if (hint != null && !hint.isBlank()) {
                for (var p : enabled) {
                    if (hint.equalsIgnoreCase(p.alias()) || hint.equalsIgnoreCase(p.providerKey())) {
                        return "redirect:" + providerStartUrl(tenant, p.alias(), p.protocol());
                    }
                }
            }
            List<ProviderButton> providers = enabled.stream()
                    .map(p -> new ProviderButton(p.displayName(), p.providerKey(),
                            providerStartUrl(tenant, p.alias(), p.protocol())))
                    .toList();
            model.addAttribute("providers", providers);
        }
        // Per-tenant sign-in branding (defaults for the root/console issuer). The color is applied via a
        // same-origin theme stylesheet (see ThemeController) so it stays within the login page's strict CSP.
        model.addAttribute("brand", branding.forTenant(tenant));
        model.addAttribute("brandTenant", tenant == null ? "" : tenant);
        return "login";
    }

    /** SAML starts at /saml2/authenticate/{id}; OIDC/OAuth2 at /oauth2/authorization/{id}. */
    private static String providerStartUrl(String tenant, String alias, String protocol) {
        String registrationId = BrokerClientRegistrationRepository.registrationId(tenant, alias);
        return "SAML".equals(protocol)
                ? "/saml2/authenticate/" + registrationId
                : "/oauth2/authorization/" + registrationId;
    }

    private static String firstParam(SavedRequest saved, String name) {
        String[] values = saved == null ? null : saved.getParameterValues(name);
        return (values == null || values.length == 0) ? null : values[0];
    }

    private String tenantFromSavedRequest(SavedRequest saved) {
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
