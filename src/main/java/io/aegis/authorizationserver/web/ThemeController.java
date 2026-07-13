package io.aegis.authorizationserver.web;

import io.aegis.authorizationserver.branding.BrandingClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * Serves the per-tenant login theme as a <strong>same-origin</strong> stylesheet, so a tenant's brand
 * color can be applied within the login page's strict CSP ({@code default-src 'self'}) without inline
 * styles. The color is re-validated here (defence in depth) to prevent any CSS injection.
 */
@RestController
public class ThemeController {

    private static final String DEFAULT_COLOR = "#3b5bdb";

    private final BrandingClient branding;

    public ThemeController(BrandingClient branding) {
        this.branding = branding;
    }

    @GetMapping(value = "/login/theme.css", produces = "text/css")
    @ResponseBody
    public String theme(@RequestParam(required = false) String tenant) {
        String color = branding.forTenant(tenant).primaryColor();
        if (color == null || !color.matches("^#[0-9a-fA-F]{6}$")) {
            color = DEFAULT_COLOR;
        }
        return ":root{--p:" + color + ";--p-hover:" + color + "}\n";
    }
}
