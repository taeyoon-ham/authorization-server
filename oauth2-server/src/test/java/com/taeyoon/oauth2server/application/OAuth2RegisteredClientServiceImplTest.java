package com.taeyoon.oauth2server.application;

import java.time.Duration;
import java.time.Instant;
import java.util.UUID;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.test.annotation.Rollback;

@SpringBootTest
class OAuth2RegisteredClientServiceImplTest {
	@Autowired
	private OAuth2RegisteredClientServiceImpl registeredClientServiceImpl;

	@Test
	@Rollback(value = false)
	void test() {

		long id = 1L;
		RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
			.clientId("andalos")
			.clientName("안달로스")
			.clientSecret("{noop}andalos1234")
			.clientIdIssuedAt(Instant.now())
			.clientSecretExpiresAt(Instant.now().plus(Duration.ofDays(30)))
			.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
			.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
			.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
			.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
			.redirectUri("http://oauth2-login.andalos.com:9010/login/oauth2/code/andalos")
			.postLogoutRedirectUri("http://oauth2-login.andalos.com:9010")
			.scope(OidcScopes.OPENID)
			.scope(OidcScopes.PROFILE)
			.clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
			.build();

		registeredClientServiceImpl.save(registeredClient);
	}

}