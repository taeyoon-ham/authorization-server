package com.taeyoon.oauth2server.application;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

import org.springframework.lang.Nullable;
import org.springframework.security.jackson2.SecurityJackson2Modules;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.jackson2.OAuth2AuthorizationServerJackson2Module;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.ConfigurationSettingNames;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.stereotype.Service;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.Module;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.taeyoon.oauth2server.domain.model.OAuth2RegisteredClientEntity;
import com.taeyoon.oauth2server.infra.persistence.OAuth2RegisteredClientRepository;

import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Service
@RequiredArgsConstructor
@Slf4j
@Transactional(rollbackOn = Exception.class)
public class OAuth2RegisteredClientServiceImpl implements RegisteredClientRepository {
	private final OAuth2RegisteredClientRepository oAuth2RegisteredClientRepository;
	private final ObjectMapper objectMapper = createObjectMapper();

	// 매우 중요. blob 에 저장/조회할때 하위 객체 타입까지 저장/조회 되어야 함.
	private ObjectMapper createObjectMapper() {
		ObjectMapper mapper = new ObjectMapper();
		ClassLoader classLoader = OAuth2RegisteredClientServiceImpl.class.getClassLoader();
		List<Module> securityModules = SecurityJackson2Modules.getModules(classLoader);
		mapper.registerModules(securityModules);
		mapper.registerModule(new OAuth2AuthorizationServerJackson2Module());
		return mapper;
	}

	@Override
	public void save(RegisteredClient registeredClient) {
		Optional<OAuth2RegisteredClientEntity> savedClientOptional = oAuth2RegisteredClientRepository.findById(
			registeredClient.getId());
		oAuth2RegisteredClientRepository.save(toEntity(registeredClient, savedClientOptional.orElse(null)));
	}

	@Override
	public RegisteredClient findById(String id) {
		Assert.hasText(id, "id cannot be empty");
		OAuth2RegisteredClientEntity client = oAuth2RegisteredClientRepository.findById(id).orElse(null);
		return toRegisteredClient(client);
	}

	@Override
	public RegisteredClient findByClientId(String clientId) {
		Assert.hasText(clientId, "clientId cannot be empty");
		OAuth2RegisteredClientEntity client = oAuth2RegisteredClientRepository.findByClientId(clientId).orElse(null);
		return toRegisteredClient(client);
	}

	private OAuth2RegisteredClientEntity toEntity(RegisteredClient client,
		@Nullable OAuth2RegisteredClientEntity entity) {
		if (entity == null) {
			entity = OAuth2RegisteredClientEntity.builder()
				.id(client.getId())
				.clientSecret(client.getClientSecret())
				.clientIdIssuedAt(Date.from(Objects.requireNonNull(client.getClientIdIssuedAt())))
				.clientSecretExpiresAt(Date.from(Objects.requireNonNull(client.getClientSecretExpiresAt())))
				.build();
		}

		List<String> clientAuthenticationMethods = new ArrayList<>(client.getClientAuthenticationMethods().size());
		client.getClientAuthenticationMethods().forEach(clientAuthenticationMethod ->
			clientAuthenticationMethods.add(clientAuthenticationMethod.getValue()));

		List<String> authorizationGrantTypes = new ArrayList<>(client.getAuthorizationGrantTypes().size());
		client.getAuthorizationGrantTypes().forEach(authorizationGrantType ->
			authorizationGrantTypes.add(authorizationGrantType.getValue()));

		entity.setClientName(client.getClientName());
		entity.setClientId(client.getClientId());
		entity.setClientAuthenticationMethods(
			StringUtils.collectionToCommaDelimitedString(clientAuthenticationMethods));
		entity.setAuthorizationGrantTypes(StringUtils.collectionToCommaDelimitedString(authorizationGrantTypes));
		entity.setRedirectUris(StringUtils.collectionToCommaDelimitedString(client.getRedirectUris()));
		entity.setPostLogoutRedirectUris(
			StringUtils.collectionToCommaDelimitedString(client.getPostLogoutRedirectUris()));
		entity.setScopes(StringUtils.collectionToCommaDelimitedString(client.getScopes()));
		entity.setClientSettings(writeMap(client.getClientSettings().getSettings()));
		entity.setTokenSettings(writeMap(client.getTokenSettings().getSettings()));

		return entity;
	}

	@Nullable
	private RegisteredClient toRegisteredClient(@Nullable OAuth2RegisteredClientEntity entity) {
		if (entity == null)
			return null;
		Set<String> clientAuthenticationMethods = StringUtils.commaDelimitedListToSet(
			entity.getClientAuthenticationMethods());
		Set<String> authorizationGrantTypes = StringUtils.commaDelimitedListToSet(entity.getAuthorizationGrantTypes());
		Set<String> redirectUris = StringUtils.commaDelimitedListToSet(entity.getRedirectUris());
		Set<String> postLogoutRedirectUris = StringUtils.commaDelimitedListToSet(entity.getPostLogoutRedirectUris());
		Set<String> clientScopes = StringUtils.commaDelimitedListToSet(entity.getScopes());
		RegisteredClient.Builder builder = RegisteredClient.withId(entity.getId())
			.clientId(entity.getClientId())
			.clientName(entity.getClientName())
			.clientIdIssuedAt(entity.getClientIdIssuedAt().toInstant())
			.clientSecret(entity.getClientSecret())
			.clientSecretExpiresAt(entity.getClientSecretExpiresAt().toInstant())
			.clientAuthenticationMethods((authenticationMethods) ->
				clientAuthenticationMethods.forEach(authenticationMethod ->
					authenticationMethods.add(resolveClientAuthenticationMethod(authenticationMethod))))
			.authorizationGrantTypes((grantTypes) ->
				authorizationGrantTypes.forEach(grantType -> grantTypes.add(resolveAuthorizationGrantType(grantType))))
			.redirectUris((uris) -> uris.addAll(redirectUris))
			.postLogoutRedirectUris((uris) -> uris.addAll(postLogoutRedirectUris))
			.scopes((scopes) -> scopes.addAll(clientScopes));

		Map<String, Object> clientSettingsMap = parseMap(entity.getClientSettings());
		builder.clientSettings(ClientSettings.withSettings(clientSettingsMap).build());

		Map<String, Object> tokenSettingsMap = parseMap(entity.getTokenSettings());
		TokenSettings.Builder tokenSettingsBuilder = TokenSettings.withSettings(tokenSettingsMap);
		if (!tokenSettingsMap.containsKey(ConfigurationSettingNames.Token.ACCESS_TOKEN_FORMAT)) {
			tokenSettingsBuilder.accessTokenFormat(OAuth2TokenFormat.SELF_CONTAINED);
		}
		builder.tokenSettings(tokenSettingsBuilder.build());

		return builder.build();
	}

	private static AuthorizationGrantType resolveAuthorizationGrantType(String authorizationGrantType) {
		if (AuthorizationGrantType.AUTHORIZATION_CODE.getValue().equals(authorizationGrantType)) {
			return AuthorizationGrantType.AUTHORIZATION_CODE;
		} else if (AuthorizationGrantType.CLIENT_CREDENTIALS.getValue().equals(authorizationGrantType)) {
			return AuthorizationGrantType.CLIENT_CREDENTIALS;
		} else if (AuthorizationGrantType.REFRESH_TOKEN.getValue().equals(authorizationGrantType)) {
			return AuthorizationGrantType.REFRESH_TOKEN;
		}
		return new AuthorizationGrantType(authorizationGrantType);        // Custom authorization grant type
	}

	private static ClientAuthenticationMethod resolveClientAuthenticationMethod(String clientAuthenticationMethod) {
		if (ClientAuthenticationMethod.CLIENT_SECRET_BASIC.getValue().equals(clientAuthenticationMethod)) {
			return ClientAuthenticationMethod.CLIENT_SECRET_BASIC;
		} else if (ClientAuthenticationMethod.CLIENT_SECRET_POST.getValue().equals(clientAuthenticationMethod)) {
			return ClientAuthenticationMethod.CLIENT_SECRET_POST;
		} else if (ClientAuthenticationMethod.NONE.getValue().equals(clientAuthenticationMethod)) {
			return ClientAuthenticationMethod.NONE;
		}
		return new ClientAuthenticationMethod(clientAuthenticationMethod);        // Custom client authentication method
	}

	private String writeMap(Map<String, Object> data) {
		try {
			return this.objectMapper.writeValueAsString(data);
		} catch (Exception ex) {
			throw new IllegalArgumentException(ex.getMessage(), ex);
		}
	}

	private Map<String, Object> parseMap(String data) {
		try {
			return this.objectMapper.readValue(data, new TypeReference<Map<String, Object>>() {
			});
		} catch (Exception ex) {
			throw new IllegalArgumentException(ex.getMessage(), ex);
		}
	}

}
