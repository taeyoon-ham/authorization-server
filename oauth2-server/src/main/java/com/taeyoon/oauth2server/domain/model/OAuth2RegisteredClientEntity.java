package com.taeyoon.oauth2server.domain.model;

import java.io.Serial;
import java.io.Serializable;
import java.util.Date;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AccessLevel;
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
@Table(name = "OAUTH2_REGISTERED_CLIENT")
public class OAuth2RegisteredClientEntity implements Serializable {

	@Serial
	private static final long serialVersionUID = -3881012048119265183L;

	@Id
	@Setter(AccessLevel.NONE)
	@Column(name = "ID")
	private String id;

	@Column(name = "CLIENT_ID")
	private String clientId;

	@Column(name = "CLIENT_ID_ISSUED_AT")
	private Date clientIdIssuedAt;

	@Column(name = "CLIENT_SECRET")
	private String clientSecret;

	@Column(name = "CLIENT_SECRET_EXPIRES_AT")
	private Date clientSecretExpiresAt;

	@Column(name = "CLIENT_NAME")
	private String clientName;

	@Column(name = "CLIENT_AUTHENTICATION_METHODS")
	private String clientAuthenticationMethods;

	@Column(name = "AUTHORIZATION_GRANT_TYPES")
	private String authorizationGrantTypes;

	@Column(name = "REDIRECT_URIS")
	private String redirectUris;

	@Column(name = "POST_LOGOUT_REDIRECT_URIS")
	private String postLogoutRedirectUris;

	@Column(name = "SCOPES")
	private String scopes;

	@Column(name = "CLIENT_SETTINGS")
	private String clientSettings;

	@Column(name = "TOKEN_SETTINGS")
	private String tokenSettings;
}