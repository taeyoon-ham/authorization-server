package com.taeyoon.oauth2server.infra.persistence;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.taeyoon.oauth2server.domain.model.OAuth2AuthorizationEntity;

public interface OAuth2AuthorizationRepository extends JpaRepository<OAuth2AuthorizationEntity, String> {
	Optional<OAuth2AuthorizationEntity> findByState(String state);
	Optional<OAuth2AuthorizationEntity> findByAuthorizationCodeValue(byte[] token);
	Optional<OAuth2AuthorizationEntity> findByAccessTokenValue(byte[] token);
	Optional<OAuth2AuthorizationEntity> findByOidcIdTokenValue(byte[] token);
	Optional<OAuth2AuthorizationEntity> findByRefreshTokenValue(byte[] token);
	Optional<OAuth2AuthorizationEntity> findByUserCodeValue(byte[] token);
	Optional<OAuth2AuthorizationEntity> findByDeviceCodeValue(byte[] token);
	Optional<OAuth2AuthorizationEntity> findByStateOrAuthorizationCodeValueOrAccessTokenValueOrOidcIdTokenValueOrRefreshTokenValueOrUserCodeValueOrDeviceCodeValue(String state, byte[] authorizationCodeValue, byte[] accessTokenValue, byte[] oidcIdTokenValue, byte[] RefreshTokenValue, byte[] userCoeValue, byte[] deviceCodeValue);
}
