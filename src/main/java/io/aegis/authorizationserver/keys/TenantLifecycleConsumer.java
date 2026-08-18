package io.aegis.authorizationserver.keys;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.aegis.authorizationserver.auth.TenantJwkSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.stereotype.Component;

/**
 * Reacts to tenant-lifecycle business events by <b>eagerly provisioning</b> the tenant's token
 * signing key — the first business-event-driven choreography in the platform (ARCHITECTURE §4.4).
 * When {@code tenant-service} creates a tenant, this consumer creates that tenant's key immediately,
 * rather than waiting for the first token request to trigger lazy creation.
 *
 * <p><b>Idempotent and floor-backed.</b> {@link TenantJwkSource#jwkSetFor(String)} is
 * compute-if-absent (backed by the store's first-writer-wins insert), so redelivery is harmless and
 * a concurrent lazy creation cannot conflict. Crucially, the lazy on-first-use path <em>remains</em>
 * as the correctness floor: if this event is lost or the consumer is down, the key is still created
 * on first use — so a dropped business event is a missed optimization, never a lost side effect. That
 * is why best-effort publishing (rather than a transactional outbox) is acceptable for this flow.
 *
 * <p>Consumes as raw JSON parsed field-by-field, so a producer on a newer event schema does not break
 * the consumer during a rolling deploy.
 */
@Component
public class TenantLifecycleConsumer {

    private static final Logger log = LoggerFactory.getLogger(TenantLifecycleConsumer.class);

    private final TenantJwkSource jwkSource;
    private final ObjectMapper mapper = new ObjectMapper();

    public TenantLifecycleConsumer(TenantJwkSource jwkSource) {
        this.jwkSource = jwkSource;
    }

    @KafkaListener(
            topics = "${aegis.tenant.lifecycle-topic:aegis.tenant.lifecycle}",
            groupId = "${aegis.tenant.consumer-group:aegis-as-key-provisioner}",
            autoStartup = "${aegis.tenant.consumer.enabled:false}")
    public void onTenantLifecycle(String json) {
        String eventType;
        String slug;
        try {
            JsonNode node = mapper.readTree(json);
            eventType = text(node, "eventType");
            slug = text(node, "slug");
        } catch (Exception e) {
            log.warn("dropping unparseable tenant-lifecycle event");
            return;
        }
        if (!"tenant.created".equals(eventType) || slug == null || slug.isBlank()) {
            return; // only act on creation; other lifecycle events are ignored here
        }
        // Eagerly provision the tenant's signing key (idempotent). This just ensures it exists.
        jwkSource.jwkSetFor(slug);
        log.info("eagerly provisioned signing key for new tenant={}", slug);
    }

    private static String text(JsonNode node, String field) {
        JsonNode v = node.get(field);
        return v != null && !v.isNull() ? v.asText() : null;
    }
}
