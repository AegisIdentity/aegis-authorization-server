package io.aegis.authorizationserver.auth;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.stereotype.Component;

@Component
public class TenantAuthenticationDetailsSource
        implements AuthenticationDetailsSource<HttpServletRequest, TenantWebAuthenticationDetails> {

    @Override
    public TenantWebAuthenticationDetails buildDetails(HttpServletRequest request) {
        return new TenantWebAuthenticationDetails(request);
    }
}
