package io.aegis.authorizationserver;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

/**
 * Proves the device user_code throttle actually fires inside the real Authorization Server filter
 * chain — not just in the filter's own unit test. The unit test proves the logic; this proves the
 * wiring (that the filter is on the chain, matches the live device-verification URI, and runs before
 * the request is otherwise handled). Both matter: a correct filter wired to the wrong path protects
 * nothing.
 */
@SpringBootTest
@ActiveProfiles("dev")
@Import(TestcontainersConfig.class)
class DeviceThrottleIT {

    @Autowired
    WebApplicationContext context;

    MockMvc mockMvc;

    @BeforeEach
    void setUp() {
        mockMvc = MockMvcBuilders.webAppContextSetup(context).apply(springSecurity()).build();
    }

    @Test
    void an_authenticated_user_is_throttled_after_the_cap_on_device_verification() throws Exception {
        // Under the cap: submissions reach the endpoint (a wrong user_code redirects back, not 429).
        for (int i = 0; i < 10; i++) {
            mockMvc.perform(post("/oauth2/device_verification")
                            .param("user_code", "WDJB-MJHT")
                            .with(user("alice"))
                            .with(org.springframework.security.test.web.servlet.request
                                    .SecurityMockMvcRequestPostProcessors.csrf()))
                    .andExpect(result -> {
                        int status = result.getResponse().getStatus();
                        org.assertj.core.api.Assertions.assertThat(status)
                                .as("under the cap, request %s must not be rate-limited", status)
                                .isNotEqualTo(429);
                    });
        }

        // Over the cap: the 11th submission by the same subject is refused with 429.
        mockMvc.perform(post("/oauth2/device_verification")
                        .param("user_code", "WDJB-MJHT")
                        .with(user("alice"))
                        .with(org.springframework.security.test.web.servlet.request
                                .SecurityMockMvcRequestPostProcessors.csrf()))
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers
                        .status().is(429));
    }

    @Test
    void a_different_user_is_not_affected_by_anothers_throttling() throws Exception {
        for (int i = 0; i < 15; i++) {
            mockMvc.perform(post("/oauth2/device_verification")
                    .param("user_code", "WDJB-MJHT")
                    .with(user("attacker"))
                    .with(org.springframework.security.test.web.servlet.request
                            .SecurityMockMvcRequestPostProcessors.csrf()));
        }

        // A different subject is unaffected — the cap is per-subject.
        mockMvc.perform(post("/oauth2/device_verification")
                        .param("user_code", "WDJB-MJHT")
                        .with(user("victim"))
                        .with(org.springframework.security.test.web.servlet.request
                                .SecurityMockMvcRequestPostProcessors.csrf()))
                .andExpect(result -> org.assertj.core.api.Assertions
                        .assertThat(result.getResponse().getStatus()).isNotEqualTo(429));
    }
}
