package io.aegis.authorizationserver.keys;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

import io.aegis.authorizationserver.auth.TenantJwkSource;
import org.junit.jupiter.api.Test;

/**
 * The eager-provisioning consumer: on a {@code tenant.created} event it provisions that tenant's
 * signing key (idempotent), and it ignores everything else and anything malformed — a business
 * consumer must not act on events it doesn't understand, nor die on a poison message.
 */
class TenantLifecycleConsumerTest {

    private final TenantJwkSource jwkSource = mock(TenantJwkSource.class);
    private final TenantLifecycleConsumer consumer = new TenantLifecycleConsumer(jwkSource);

    @Test
    void a_tenant_created_event_eagerly_provisions_the_tenant_key() {
        consumer.onTenantLifecycle(
                "{\"eventType\":\"tenant.created\",\"tenantId\":\"acme\",\"slug\":\"acme\"}");

        verify(jwkSource).jwkSetFor("acme");
    }

    @Test
    void a_non_creation_event_provisions_nothing() {
        consumer.onTenantLifecycle(
                "{\"eventType\":\"tenant.suspended\",\"slug\":\"acme\"}");

        verify(jwkSource, never()).jwkSetFor(org.mockito.ArgumentMatchers.any());
    }

    @Test
    void an_event_with_no_slug_provisions_nothing() {
        consumer.onTenantLifecycle("{\"eventType\":\"tenant.created\"}");

        verify(jwkSource, never()).jwkSetFor(org.mockito.ArgumentMatchers.any());
    }

    @Test
    void a_malformed_message_is_dropped_not_thrown() {
        // Must not throw — a poison message cannot be allowed to block the partition.
        consumer.onTenantLifecycle("{not json");

        verify(jwkSource, never()).jwkSetFor(org.mockito.ArgumentMatchers.any());
    }
}
