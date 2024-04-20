package com.taeyoon.oauth2server.application;

import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

import org.springframework.dao.DataRetrievalFailureException;
import org.springframework.lang.Nullable;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.stereotype.Service;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import com.taeyoon.oauth2server.domain.model.OAuth2AuthorizationConsentEntity;
import com.taeyoon.oauth2server.domain.model.OAuth2AuthorizationConsentEntityId;
import com.taeyoon.oauth2server.infra.persistence.OAuth2AuthorizationConsentRepository;

import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Service
@RequiredArgsConstructor
@Slf4j
@Transactional(rollbackOn = Exception.class)
public class OAuth2AuthorizationConsentServiceImpl implements OAuth2AuthorizationConsentService {
	private final OAuth2AuthorizationConsentRepository authorizationConsentRepository;
	private final OAuth2RegisteredClientServiceImpl oAuth2RegisteredClientServiceImpl;

	@Override
	public void save(OAuth2AuthorizationConsent consent) {
		Assert.notNull(consent, "authorizationConsent cannot be null");
		OAuth2AuthorizationConsentEntityId id = OAuth2AuthorizationConsentEntityId.builder()
			.registeredClientId(consent.getRegisteredClientId())
			.principalName(consent.getPrincipalName())
			.build();
		Optional<OAuth2AuthorizationConsentEntity> savedConsentOptional = authorizationConsentRepository.findById(id);
		authorizationConsentRepository.save(toEntity(consent, savedConsentOptional.orElse(null)));
	}

	@Override
	public void remove(OAuth2AuthorizationConsent consent) {
		Assert.notNull(consent, "authorizationConsent cannot be null");
		OAuth2AuthorizationConsentEntityId id = OAuth2AuthorizationConsentEntityId.builder()
			.registeredClientId(consent.getRegisteredClientId())
			.principalName(consent.getPrincipalName())
			.build();
		Optional<OAuth2AuthorizationConsentEntity> savedConsentOptional = authorizationConsentRepository.findById(id);
		savedConsentOptional.ifPresent(authorizationConsentRepository::delete);
	}

	@Nullable
	@Override
	public OAuth2AuthorizationConsent findById(String registeredClientId, String principalName) {
		Assert.hasText(registeredClientId, "registeredClientId cannot be empty");
		Assert.hasText(principalName, "principalName cannot be empty");
		OAuth2AuthorizationConsentEntityId id = OAuth2AuthorizationConsentEntityId.builder()
			.registeredClientId(registeredClientId)
			.principalName(principalName)
			.build();
		OAuth2AuthorizationConsentEntity savedConsent = authorizationConsentRepository.findById(id).orElse(null);

		RegisteredClient registeredClient = oAuth2RegisteredClientServiceImpl.findById(registeredClientId);
		if (registeredClient == null) {
			throw new DataRetrievalFailureException(
				"The RegisteredClient with id '" + registeredClientId + "' was not found in the RegisteredClientRepository.");
		}
		return toOAuth2AuthorizationConsent(savedConsent);
	}

	@Nullable
	private OAuth2AuthorizationConsent toOAuth2AuthorizationConsent(@Nullable OAuth2AuthorizationConsentEntity consent) {
		if (consent == null) return null;
		OAuth2AuthorizationConsent.Builder builder = OAuth2AuthorizationConsent.withId(consent.getId().getRegisteredClientId(), consent.getId().getPrincipalName());
		String authorizationConsentAuthorities = consent.getAuthorities();
		if (authorizationConsentAuthorities != null) {
			for (String authority : StringUtils.commaDelimitedListToSet(authorizationConsentAuthorities)) {
				builder.authority(new SimpleGrantedAuthority(authority));
			}
		}
		return builder.build();
	}

	private OAuth2AuthorizationConsentEntity toEntity(OAuth2AuthorizationConsent consent, OAuth2AuthorizationConsentEntity entity) {
		if (entity == null) {
			entity = OAuth2AuthorizationConsentEntity.builder().build();
		}
		Set<String> authorities = new HashSet<>();
		for (GrantedAuthority authority : consent.getAuthorities()) {
			authorities.add(authority.getAuthority());
		}
		OAuth2AuthorizationConsentEntityId id = OAuth2AuthorizationConsentEntityId.builder()
			.registeredClientId(consent.getRegisteredClientId())
			.principalName(consent.getPrincipalName())
			.build();
		entity.setId(id);
		entity.setAuthorities(StringUtils.collectionToDelimitedString(authorities, ","));
		return entity;
	}
}
