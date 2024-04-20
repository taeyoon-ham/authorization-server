package com.taeyoon.oauth2server.application;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import org.springframework.lang.Nullable;
import org.springframework.security.jackson2.SecurityJackson2Modules;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2DeviceCode;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.OAuth2UserCode;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.jackson2.OAuth2AuthorizationServerJackson2Module;
import org.springframework.stereotype.Service;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.Module;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.taeyoon.oauth2server.domain.model.OAuth2AuthorizationEntity;
import com.taeyoon.oauth2server.infra.persistence.OAuth2AuthorizationRepository;
import com.taeyoon.oauth2server.infra.utils.StringUtils;

import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Service
@RequiredArgsConstructor
@Slf4j
@Transactional(rollbackOn = Exception.class)
public class OAuth2AuthorizationServiceImpl implements OAuth2AuthorizationService {
	private final OAuth2AuthorizationRepository oAuth2AuthorizationRepository;
	private final OAuth2RegisteredClientServiceImpl oAuth2RegisteredClientServiceImpl;
	private final ObjectMapper objectMapper = createObjectMapper();

	// 매우 중요. blob 에 저장/조회할때 하위 객체 타입까지 저장/조회 되어야 함.
	private ObjectMapper createObjectMapper() {
		ObjectMapper mapper = new ObjectMapper();
		ClassLoader classLoader = OAuth2AuthorizationServiceImpl.class.getClassLoader();
		List<Module> securityModules = SecurityJackson2Modules.getModules(classLoader);
		mapper.registerModules(securityModules);
		mapper.registerModule(new OAuth2AuthorizationServerJackson2Module());
		return mapper;
	}

	@Override
	public void save(OAuth2Authorization authorization) {
		Optional<OAuth2AuthorizationEntity> savedAuthOptional = oAuth2AuthorizationRepository.findById(
			authorization.getId());
		oAuth2AuthorizationRepository.save(toEntity(authorization, savedAuthOptional.orElse(null)));
	}

	@Override
	public void remove(OAuth2Authorization authorization) {
		Assert.notNull(authorization, "authorization cannot be null");
		oAuth2AuthorizationRepository.deleteById(authorization.getId());
	}

	@Nullable
	@Override
	public OAuth2Authorization findById(String id) {
		Assert.hasText(id, "id cannot be empty");
		OAuth2AuthorizationEntity auth = oAuth2AuthorizationRepository.findById(id).orElse(null);
		return toOAuth2Authorization(auth);
	}

	@Nullable
	@Override
	public OAuth2Authorization findByToken(String token,
		@Nullable OAuth2TokenType tokenType) {
		Assert.hasText(token, "token cannot be empty");
		byte[] tokenByte = token.getBytes(StandardCharsets.UTF_8);
		if (tokenType == null) {
			return toOAuth2Authorization(
				oAuth2AuthorizationRepository.findByStateOrAuthorizationCodeValueOrAccessTokenValueOrOidcIdTokenValueOrRefreshTokenValueOrUserCodeValueOrDeviceCodeValue(
					token, tokenByte, tokenByte, tokenByte, tokenByte, tokenByte, tokenByte).orElse(null));
		} else if (OAuth2ParameterNames.STATE.equals(tokenType.getValue())) {
			return toOAuth2Authorization(oAuth2AuthorizationRepository.findByState(token).orElse(null));
		} else if (OAuth2ParameterNames.CODE.equals(tokenType.getValue())) {
			return toOAuth2Authorization(
				oAuth2AuthorizationRepository.findByAuthorizationCodeValue(tokenByte).orElse(null));
		} else if (OAuth2TokenType.ACCESS_TOKEN.equals(tokenType)) {
			return toOAuth2Authorization(oAuth2AuthorizationRepository.findByAccessTokenValue(tokenByte).orElse(null));
		} else if (OidcParameterNames.ID_TOKEN.equals(tokenType.getValue())) {
			return toOAuth2Authorization(oAuth2AuthorizationRepository.findByOidcIdTokenValue(tokenByte).orElse(null));
		} else if (OAuth2TokenType.REFRESH_TOKEN.equals(tokenType)) {
			return toOAuth2Authorization(oAuth2AuthorizationRepository.findByRefreshTokenValue(tokenByte).orElse(null));
		} else if (OAuth2ParameterNames.USER_CODE.equals(tokenType.getValue())) {
			return toOAuth2Authorization(oAuth2AuthorizationRepository.findByUserCodeValue(tokenByte).orElse(null));
		} else if (OAuth2ParameterNames.DEVICE_CODE.equals(tokenType.getValue())) {
			return toOAuth2Authorization(oAuth2AuthorizationRepository.findByDeviceCodeValue(tokenByte).orElse(null));
		}
		return null;
	}

	private OAuth2AuthorizationEntity toEntity(OAuth2Authorization auth, OAuth2AuthorizationEntity entity) {
		if (entity == null) {
			entity = OAuth2AuthorizationEntity.builder()
				.id(UUID.randomUUID().toString())
				.build();
		}
		entity.setRegisteredClientId(auth.getRegisteredClientId());
		entity.setPrincipalName(auth.getPrincipalName());
		entity.setAuthorizationGrantType(auth.getAuthorizationGrantType().getValue());

		if (!CollectionUtils.isEmpty(auth.getAuthorizedScopes())) {
			entity.setAuthorizedScopes(StringUtils.collectionToDelimitedString(auth.getAuthorizedScopes(), ","));
		}
		entity.setAttributes(writeMap(auth.getAttributes()).getBytes());

		String authorizationState = auth.getAttribute(OAuth2ParameterNames.STATE);
		if (StringUtils.hasText(authorizationState)) {
			entity.setState(authorizationState);
		}

		OAuth2Authorization.Token<OAuth2AuthorizationCode> authorizationCode = auth.getToken(
			OAuth2AuthorizationCode.class);
		if (authorizationCode != null) {
			entity.setAuthorizationCodeValue(
				authorizationCode.getToken().getTokenValue().getBytes(StandardCharsets.UTF_8));
			entity.setAuthorizationCodeMetadata(
				writeMap(authorizationCode.getMetadata()).getBytes(StandardCharsets.UTF_8));
			if (authorizationCode.getToken().getIssuedAt() != null) {
				entity.setAuthorizationCodeIssuedAt(Date.from(authorizationCode.getToken().getIssuedAt()));
			}
			if (authorizationCode.getToken().getExpiresAt() != null) {
				entity.setAuthorizationCodeExpiresAt(Date.from(authorizationCode.getToken().getExpiresAt()));
			}
		}

		OAuth2Authorization.Token<OAuth2AccessToken> accessToken = auth.getToken(OAuth2AccessToken.class);
		if (accessToken != null) {
			entity.setAccessTokenValue(
				accessToken.getToken().getTokenValue().getBytes(StandardCharsets.UTF_8));
			entity.setAccessTokenMetadata(
				writeMap(accessToken.getMetadata()).getBytes(StandardCharsets.UTF_8));
			entity.setAccessTokenType(accessToken.getToken().getTokenType().getValue());
			if (!CollectionUtils.isEmpty(accessToken.getToken().getScopes())) {
				entity.setAccessTokenScopes(
					StringUtils.collectionToDelimitedString(accessToken.getToken().getScopes(), ","));
			}
			if (accessToken.getToken().getIssuedAt() != null) {
				entity.setAccessTokenIssuedAt(Date.from(accessToken.getToken().getIssuedAt()));
			}
			if (accessToken.getToken().getExpiresAt() != null) {
				entity.setAccessTokenExpiresAt(Date.from(accessToken.getToken().getExpiresAt()));
			}
		}

		OAuth2Authorization.Token<OidcIdToken> oidcIdToken = auth.getToken(OidcIdToken.class);
		if (oidcIdToken != null) {
			entity.setOidcIdTokenValue(
				oidcIdToken.getToken().getTokenValue().getBytes(StandardCharsets.UTF_8));
			entity.setOidcIdTokenMetadata(
				writeMap(oidcIdToken.getMetadata()).getBytes(StandardCharsets.UTF_8));
			if (oidcIdToken.getToken().getIssuedAt() != null) {
				entity.setOidcIdTokenIssuedAt(Date.from(oidcIdToken.getToken().getIssuedAt()));
			}
			if (oidcIdToken.getToken().getExpiresAt() != null) {
				entity.setOidcIdTokenExpiresAt(Date.from(oidcIdToken.getToken().getExpiresAt()));
			}
		}

		OAuth2Authorization.Token<OAuth2RefreshToken> refreshToken = auth.getToken(OAuth2RefreshToken.class);
		if (refreshToken != null) {
			entity.setRefreshTokenValue(
				refreshToken.getToken().getTokenValue().getBytes(StandardCharsets.UTF_8));
			entity.setRefreshTokenMetadata(
				writeMap(refreshToken.getMetadata()).getBytes(StandardCharsets.UTF_8));
			if (refreshToken.getToken().getIssuedAt() != null) {
				entity.setRefreshTokenIssuedAt(Date.from(refreshToken.getToken().getIssuedAt()));
			}
			if (refreshToken.getToken().getExpiresAt() != null) {
				entity.setRefreshTokenExpiresAt(Date.from(refreshToken.getToken().getExpiresAt()));
			}
		}

		OAuth2Authorization.Token<OAuth2UserCode> userCode = auth.getToken(OAuth2UserCode.class);
		if (userCode != null) {
			entity.setUserCodeValue(
				userCode.getToken().getTokenValue().getBytes(StandardCharsets.UTF_8));
			entity.setUserCodeMetadata(
				writeMap(userCode.getMetadata()).getBytes(StandardCharsets.UTF_8));
			if (userCode.getToken().getIssuedAt() != null) {
				entity.setUserCodeIssuedAt(Date.from(userCode.getToken().getIssuedAt()));
			}
			if (userCode.getToken().getExpiresAt() != null) {
				entity.setUserCodeExpiresAt(Date.from(userCode.getToken().getExpiresAt()));
			}
		}

		OAuth2Authorization.Token<OAuth2DeviceCode> deviceCode = auth.getToken(OAuth2DeviceCode.class);
		if (deviceCode != null) {
			entity.setDeviceCodeValue(
				deviceCode.getToken().getTokenValue().getBytes(StandardCharsets.UTF_8));
			entity.setDeviceCodeMetadata(
				writeMap(deviceCode.getMetadata()).getBytes(StandardCharsets.UTF_8));
			if (deviceCode.getToken().getIssuedAt() != null) {
				entity.setDeviceCodeIssuedAt(Date.from(deviceCode.getToken().getIssuedAt()));
			}
			if (deviceCode.getToken().getExpiresAt() != null) {
				entity.setDeviceCodeExpiresAt(Date.from(deviceCode.getToken().getExpiresAt()));
			}
		}

		return entity;
	}

	@SuppressWarnings("unchecked")
	private OAuth2Authorization toOAuth2Authorization(@Nullable OAuth2AuthorizationEntity auth) {
		if (auth == null)
			return null;
		Set<String> authorizedScopes = Collections.emptySet();
		String authorizedScopesString = auth.getAuthorizedScopes();
		if (authorizedScopesString != null) {
			authorizedScopes = StringUtils.commaDelimitedListToSet(authorizedScopesString);
		}

		Map<String, Object> attributes = parseMap(
			new String(auth.getAttributes(), StandardCharsets.UTF_8));
		RegisteredClient client = oAuth2RegisteredClientServiceImpl.findById(auth.getRegisteredClientId());
		Assert.notNull(client, "registeredClient cannot be null");

		OAuth2Authorization.Builder builder = OAuth2Authorization.withRegisteredClient(client);
		builder
			.id(auth.getId())
			.principalName(auth.getPrincipalName())
			.authorizationGrantType(new AuthorizationGrantType(auth.getAuthorizationGrantType()))
			.authorizedScopes(authorizedScopes)
			.attributes((attr) -> attr.putAll(attributes));

		String state = auth.getState();
		if (StringUtils.hasText(state)) {
			builder.attribute(OAuth2ParameterNames.STATE, state);
		}

		Instant tokenIssuedAt;
		Instant tokenExpiresAt;
		String authorizationCodeValue = StringUtils.byteToString(auth.getAuthorizationCodeValue());
		if (StringUtils.hasText(authorizationCodeValue)) {
			tokenIssuedAt = auth.getAuthorizationCodeIssuedAt().toInstant();
			tokenExpiresAt = auth.getAuthorizationCodeExpiresAt().toInstant();
			Map<String, Object> authorizationCodeMetadata = parseMap(
				new String(auth.getAuthorizationCodeMetadata(), StandardCharsets.UTF_8));

			OAuth2AuthorizationCode authorizationCode = new OAuth2AuthorizationCode(
				authorizationCodeValue, tokenIssuedAt, tokenExpiresAt);
			builder.token(authorizationCode, (metadata) -> metadata.putAll(authorizationCodeMetadata));
		}

		String accessTokenValue = StringUtils.byteToString(auth.getAccessTokenValue());
		if (StringUtils.hasText(accessTokenValue)) {
			tokenIssuedAt = auth.getAccessTokenIssuedAt().toInstant();
			tokenExpiresAt = auth.getAccessTokenExpiresAt().toInstant();
			Map<String, Object> accessTokenMetadata = parseMap(
				new String(auth.getAccessTokenMetadata(), StandardCharsets.UTF_8));
			OAuth2AccessToken.TokenType tokenType = null;
			if (OAuth2AccessToken.TokenType.BEARER.getValue().equalsIgnoreCase(auth.getAccessTokenType())) {
				tokenType = OAuth2AccessToken.TokenType.BEARER;
			}

			Set<String> scopes = Collections.emptySet();
			String accessTokenScopes = auth.getAccessTokenScopes();
			if (accessTokenScopes != null) {
				scopes = StringUtils.commaDelimitedListToSet(accessTokenScopes);
			}
			OAuth2AccessToken accessToken = new OAuth2AccessToken(tokenType, accessTokenValue, tokenIssuedAt,
				tokenExpiresAt, scopes);
			builder.token(accessToken, (metadata) -> metadata.putAll(accessTokenMetadata));
		}

		String oidcIdTokenValue = StringUtils.byteToString(auth.getOidcIdTokenValue());
		if (StringUtils.hasText(oidcIdTokenValue)) {
			tokenIssuedAt = auth.getOidcIdTokenIssuedAt().toInstant();
			tokenExpiresAt = auth.getOidcIdTokenExpiresAt().toInstant();
			Map<String, Object> oidcTokenMetadata = parseMap(
				new String(auth.getOidcIdTokenMetadata(), StandardCharsets.UTF_8));

			OidcIdToken oidcToken = new OidcIdToken(
				oidcIdTokenValue, tokenIssuedAt, tokenExpiresAt,
				(Map<String, Object>)oidcTokenMetadata.get(OAuth2Authorization.Token.CLAIMS_METADATA_NAME));
			builder.token(oidcToken, (metadata) -> metadata.putAll(oidcTokenMetadata));
		}

		String refreshTokenValue = StringUtils.byteToString(auth.getRefreshTokenValue());
		if (StringUtils.hasText(refreshTokenValue)) {
			tokenIssuedAt = auth.getRefreshTokenIssuedAt().toInstant();
			tokenExpiresAt = null;
			if (auth.getRefreshTokenExpiresAt() != null) {
				tokenExpiresAt = auth.getRefreshTokenExpiresAt().toInstant();
			}
			Map<String, Object> refreshTokenMetadata = parseMap(
				new String(auth.getRefreshTokenMetadata(), StandardCharsets.UTF_8));

			OAuth2RefreshToken refreshToken = new OAuth2RefreshToken(
				refreshTokenValue, tokenIssuedAt, tokenExpiresAt);
			builder.token(refreshToken, (metadata) -> metadata.putAll(refreshTokenMetadata));
		}

		String userCodeValue = StringUtils.byteToString(auth.getUserCodeValue());
		if (StringUtils.hasText(userCodeValue)) {
			tokenIssuedAt = auth.getUserCodeIssuedAt().toInstant();
			tokenExpiresAt = auth.getUserCodeExpiresAt().toInstant();
			Map<String, Object> userCodeMetadata = parseMap(
				new String(auth.getUserCodeMetadata(), StandardCharsets.UTF_8));

			OAuth2UserCode userCode = new OAuth2UserCode(userCodeValue, tokenIssuedAt, tokenExpiresAt);
			builder.token(userCode, (metadata) -> metadata.putAll(userCodeMetadata));
		}

		String deviceCodeValue = StringUtils.byteToString(auth.getDeviceCodeValue());
		if (StringUtils.hasText(deviceCodeValue)) {
			tokenIssuedAt = auth.getDeviceCodeIssuedAt().toInstant();
			tokenExpiresAt = auth.getDeviceCodeExpiresAt().toInstant();
			Map<String, Object> deviceCodeMetadata = parseMap(
				new String(auth.getDeviceCodeMetadata(), StandardCharsets.UTF_8));

			OAuth2DeviceCode deviceCode = new OAuth2DeviceCode(deviceCodeValue, tokenIssuedAt, tokenExpiresAt);
			builder.token(deviceCode, (metadata) -> metadata.putAll(deviceCodeMetadata));
		}

		return builder.build();
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
