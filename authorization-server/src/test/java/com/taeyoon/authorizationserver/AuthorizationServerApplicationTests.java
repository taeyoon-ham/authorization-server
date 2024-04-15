package com.taeyoon.authorizationserver;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

import java.util.Map;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class AuthorizationServerApplicationTests {

	private static final String TOKEN_URL = "/oauth2/v1/token";
	private static final String INTROSPECT_URL = "/oauth2/v1/introspect";
	private static final String CLIENT_ID = "messaging-client";

	private static final String CLIENT_SECRET = "secret";

	private final ObjectMapper objectMapper = new ObjectMapper();

	@Autowired
	private MockMvc mockMvc;

	@Test
	void performTokenRequestWhenValidClientCredentialsThenOk() throws Exception {
		// @formatter:off
		this.mockMvc.perform(post(TOKEN_URL)
				.param("grant_type", "client_credentials")
				.param("scope", "message:read")
				.with(httpBasic(CLIENT_ID, CLIENT_SECRET)))
			.andExpect(status().isOk())
			.andExpect(jsonPath("$.access_token").isString())
			.andExpect(jsonPath("$.expires_in").isNumber())
			.andExpect(jsonPath("$.scope").value("message:read"))
			.andExpect(jsonPath("$.token_type").value("Bearer"));
		// @formatter:on
	}

	@Test
	void performTokenRequestWhenMissingScopeThenOk() throws Exception {
		// @formatter:off
		this.mockMvc.perform(post(TOKEN_URL)
				.param("grant_type", "client_credentials")
				.param("scope", "message:read message:write")
				.with(httpBasic(CLIENT_ID, CLIENT_SECRET)))
			.andExpect(status().isOk())
			.andExpect(jsonPath("$.access_token").isString())
			.andExpect(jsonPath("$.expires_in").isNumber())
			.andExpect(jsonPath("$.scope").value("message:read message:write"))
			.andExpect(jsonPath("$.token_type").value("Bearer"));
		// @formatter:on
	}

	@Test
	void performTokenRequestWhenInvalidClientCredentialsThenUnauthorized() throws Exception {
		// @formatter:off
		this.mockMvc.perform(post(TOKEN_URL)
				.param("grant_type", "client_credentials")
				.param("scope", "message:read")
				.with(httpBasic("bad", "password")))
			.andExpect(status().isUnauthorized())
			.andExpect(jsonPath("$.error").value("invalid_client"));
		// @formatter:on
	}

	@Test
	void performTokenRequestWhenMissingGrantTypeThenUnauthorized() throws Exception {
		// @formatter:off
		this.mockMvc.perform(post(TOKEN_URL)
				.with(httpBasic("bad", "password")))
			.andExpect(status().isUnauthorized())
			.andExpect(jsonPath("$.error").value("invalid_client"));
		// @formatter:on
	}

	@Test
	void performTokenRequestWhenGrantTypeNotRegisteredThenBadRequest() throws Exception {
		// @formatter:off
		this.mockMvc.perform(post(TOKEN_URL)
				.param("grant_type", "client_credentials")
				.with(httpBasic("login-client", "openid-connect")))
			.andExpect(status().isBadRequest())
			.andExpect(jsonPath("$.error").value("unauthorized_client"));
		// @formatter:on
	}

	@Test
	void performIntrospectionRequestWhenValidTokenThenOk() throws Exception {
		// @formatter:off
		this.mockMvc.perform(post(INTROSPECT_URL)
				.param("token", getAccessToken())
				.with(httpBasic(CLIENT_ID, CLIENT_SECRET)))
			.andExpect(status().isOk())
			.andExpect(jsonPath("$.active").value("true"))
			.andExpect(jsonPath("$.aud[0]").value(CLIENT_ID))
			.andExpect(jsonPath("$.client_id").value(CLIENT_ID))
			.andExpect(jsonPath("$.exp").isNumber())
			.andExpect(jsonPath("$.iat").isNumber())
			.andExpect(jsonPath("$.iss").value("http://localhost:9000"))
			.andExpect(jsonPath("$.nbf").isNumber())
			.andExpect(jsonPath("$.scope").value("message:read"))
			.andExpect(jsonPath("$.sub").value(CLIENT_ID))
			.andExpect(jsonPath("$.token_type").value("Bearer"));
		// @formatter:on
	}

	@Test
	void performIntrospectionRequestWhenInvalidCredentialsThenUnauthorized() throws Exception {
		// @formatter:off
		this.mockMvc.perform(post(INTROSPECT_URL)
				.param("token", getAccessToken())
				.with(httpBasic("bad", "password")))
			.andExpect(status().isUnauthorized())
			.andExpect(jsonPath("$.error").value("invalid_client"));
		// @formatter:on
	}

	private String getAccessToken() throws Exception {
		// @formatter:off
		MvcResult mvcResult = this.mockMvc.perform(post(TOKEN_URL)
				.param("grant_type", "client_credentials")
				.param("scope", "message:read")
				.with(httpBasic(CLIENT_ID, CLIENT_SECRET)))
			.andExpect(status().isOk())
			.andExpect(jsonPath("$.access_token").exists())
			.andReturn();
		// @formatter:on

		String tokenResponseJson = mvcResult.getResponse().getContentAsString();
		Map<String, Object> tokenResponse = this.objectMapper.readValue(tokenResponseJson, new TypeReference<>() {
		});

		return tokenResponse.get("access_token").toString();
	}

}
