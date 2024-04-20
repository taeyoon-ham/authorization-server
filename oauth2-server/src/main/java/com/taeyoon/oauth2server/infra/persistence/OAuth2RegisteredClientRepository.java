package com.taeyoon.oauth2server.infra.persistence;


import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.taeyoon.oauth2server.domain.model.OAuth2RegisteredClientEntity;

public interface OAuth2RegisteredClientRepository extends JpaRepository<OAuth2RegisteredClientEntity, String> {
	Optional<OAuth2RegisteredClientEntity> findByClientId(String clientId);
}
