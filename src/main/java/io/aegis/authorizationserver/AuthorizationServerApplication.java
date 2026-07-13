package io.aegis.authorizationserver;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Aegis Authorization Server — the OIDC/OAuth2 provider and interactive-login host.
 * See {@code aegis-platform-docs/architecture/SERVICE-CATALOG.md} for the contract.
 */
@SpringBootApplication
public class AuthorizationServerApplication {

    public static void main(String[] args) {
        SpringApplication.run(AuthorizationServerApplication.class, args);
    }
}
