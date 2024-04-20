package com.taeyoon.oauth2server.infra.persistence;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.taeyoon.oauth2server.domain.model.OAuth2AuthorizationConsentEntity;
import com.taeyoon.oauth2server.domain.model.OAuth2AuthorizationConsentEntityId;

public interface OAuth2AuthorizationConsentRepository extends JpaRepository<OAuth2AuthorizationConsentEntity, OAuth2AuthorizationConsentEntityId> {
}
