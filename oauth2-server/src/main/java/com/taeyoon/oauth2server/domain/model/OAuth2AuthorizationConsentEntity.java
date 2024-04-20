package com.taeyoon.oauth2server.domain.model;

import java.io.Serial;
import java.io.Serializable;

import jakarta.persistence.Column;
import jakarta.persistence.EmbeddedId;
import jakarta.persistence.Entity;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Builder
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "OAUTH2_AUTHORIZATION_CONSENT")
public class OAuth2AuthorizationConsentEntity implements Serializable {

	@Serial
	private static final long serialVersionUID = 6312908721246300562L;

	@EmbeddedId
	private OAuth2AuthorizationConsentEntityId id;
	@Column(name = "AUTHORITIES")
	private String authorities;
}
