package io.aegis.authorizationserver.web;

import io.aegis.authorizationserver.service.ApplicationAdminService;
import io.aegis.authorizationserver.web.ApplicationDtos.ApplicationSummary;
import io.aegis.authorizationserver.web.ApplicationDtos.CreateApplicationRequest;
import jakarta.validation.Valid;
import java.net.URI;
import java.util.List;
import org.springframework.http.ResponseEntity;
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

    @DeleteMapping("/api/v1/applications/{id}")
    public ResponseEntity<Void> delete(@PathVariable String id) {
        applications.delete(id);
        return ResponseEntity.noContent().build();
    }
}
