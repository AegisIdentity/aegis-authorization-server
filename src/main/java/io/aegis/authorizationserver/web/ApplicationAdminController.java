package io.aegis.authorizationserver.web;

import io.aegis.authorizationserver.service.ApplicationAdminService;
import io.aegis.authorizationserver.web.ApplicationDtos.ApplicationSummary;
import io.aegis.authorizationserver.web.ApplicationDtos.CreateApplicationRequest;
import io.aegis.authorizationserver.web.ApplicationDtos.CreateServiceApplicationRequest;
import io.aegis.authorizationserver.web.ApplicationDtos.ServiceApplicationCreated;
import jakarta.validation.Valid;
import java.net.URI;
import java.util.List;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

/** Admin API for OAuth2 registered clients. Secured by {@code SCOPE_applications:admin}
 * (see {@code ApiSecurityConfig}). */
@RestController
public class ApplicationAdminController {

    private final ApplicationAdminService applications;

    public ApplicationAdminController(ApplicationAdminService applications) {
        this.applications = applications;
    }

    @GetMapping("/api/v1/applications")
    public List<ApplicationSummary> list() {
        return applications.list();
    }

    @PostMapping("/api/v1/applications")
    public ResponseEntity<ApplicationSummary> create(@Valid @RequestBody CreateApplicationRequest request) {
        ApplicationSummary created = applications.createOidc(request.name(), request.redirectUri());
        return ResponseEntity.created(URI.create("/api/v1/applications/" + created.id())).body(created);
    }

    /**
     * Registers a service (M2M) application for the caller's tenant. The tenant is taken from the
     * caller's own access token ({@code tenant} claim) — never from the request body — so an admin can
     * only create service clients within their own organization. The generated secret is in the
     * response body and is shown only this once.
     */
    @PostMapping("/api/v1/applications/service")
    public ResponseEntity<ServiceApplicationCreated> createService(
            @Valid @RequestBody CreateServiceApplicationRequest request,
            @AuthenticationPrincipal Jwt caller) {
        String tenant = caller.getClaimAsString("tenant");
        ServiceApplicationCreated created = applications.createService(tenant, request.name(), request.scopes());
        return ResponseEntity.created(URI.create("/api/v1/applications/" + created.id())).body(created);
    }

    @DeleteMapping("/api/v1/applications/{id}")
    public ResponseEntity<Void> delete(@PathVariable String id) {
        applications.delete(id);
        return ResponseEntity.noContent().build();
    }
}
