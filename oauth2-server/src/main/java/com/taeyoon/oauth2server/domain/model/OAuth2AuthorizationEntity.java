package com.taeyoon.oauth2server.domain.model;

import java.io.Serial;
import java.io.Serializable;
import java.util.Date;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Lob;
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
@Table(name = "OAUTH2_AUTHORIZATION")
public class OAuth2AuthorizationEntity implements Serializable {

	@Serial
	private static final long serialVersionUID = -7159025923844480360L;
	@Id
	@Setter(AccessLevel.NONE)
	@Column(name = "ID")
	private String id;

	@Column(name = "REGISTERED_CLIENT_ID")
	private String registeredClientId;
	@Column(name = "PRINCIPAL_NAME")
	private String principalName;
	@Column(name = "AUTHORIZATION_GRANT_TYPE")
	private String authorizationGrantType;
	@Column(name = "AUTHORIZED_SCOPES")
	private String authorizedScopes;

	@Lob
	@Column(name = "ATTRIBUTES", columnDefinition="BLOB")
	private byte[] attributes;
	@Column(name = "STATE")
	private String state;
	@Lob
	@Column(name = "AUTHORIZATION_CODE_VALUE", columnDefinition="BLOB")
	private byte[] authorizationCodeValue;
	@Column(name = "AUTHORIZATION_CODE_ISSUED_AT")
	private Date authorizationCodeIssuedAt;
	@Column(name = "AUTHORIZATION_CODE_EXPIRES_AT")
	private Date authorizationCodeExpiresAt;
	@Lob
	@Column(name = "authorization_code_metadata", columnDefinition="BLOB")
	private byte[] authorizationCodeMetadata;
	@Lob
	@Column(name = "access_token_value", columnDefinition="BLOB")
	private byte[] accessTokenValue;
	@Column(name = "ACCESS_TOKEN_ISSUED_AT")
	private Date accessTokenIssuedAt;
	@Column(name = "ACCESS_TOKEN_EXPIRES_AT")
	private Date accessTokenExpiresAt;
	@Lob
	@Column(name = "ACCESS_TOKEN_METADATA", columnDefinition="BLOB")
	private byte[] accessTokenMetadata;
	@Column(name = "ACCESS_TOKEN_TYPE")
	private String accessTokenType;
	@Column(name = "ACCESS_TOKEN_SCOPES")
	private String accessTokenScopes;
	@Lob
	@Column(name = "OIDC_ID_TOKEN_VALUE", columnDefinition="BLOB")
	private byte[] oidcIdTokenValue;
	@Column(name = "OIDC_ID_TOKEN_ISSUED_AT")
	private Date oidcIdTokenIssuedAt;
	@Column(name = "OIDC_ID_TOKEN_EXPIRES_AT")
	private Date oidcIdTokenExpiresAt;
	@Lob
	@Column(name = "OIDC_ID_TOKEN_METADATA", columnDefinition="BLOB")
	private byte[] oidcIdTokenMetadata;
	@Lob
	@Column(name = "REFRESH_TOKEN_VALUE", columnDefinition="BLOB")
	private byte[] refreshTokenValue;
	@Column(name = "REFRESH_TOKEN_ISSUED_AT")
	private Date refreshTokenIssuedAt;
	@Column(name = "REFRESH_TOKEN_EXPIRES_AT")
	private Date refreshTokenExpiresAt;
	@Lob
	@Column(name = "REFRESH_TOKEN_METADATA", columnDefinition="BLOB")
	private byte[] refreshTokenMetadata;
	@Lob
	@Column(name = "USER_CODE_VALUE", columnDefinition="BLOB")
	private byte[] userCodeValue;
	@Column(name = "USER_CODE_ISSUED_AT")
	private Date userCodeIssuedAt;
	@Column(name = "USER_CODE_EXPIRES_AT")
	private Date userCodeExpiresAt;
	@Lob
	@Column(name = "USER_CODE_METADATA", columnDefinition="BLOB")
	private byte[] userCodeMetadata;
	@Lob
	@Column(name = "DEVICE_CODE_VALUE", columnDefinition="BLOB")
	private byte[] deviceCodeValue;
	@Column(name = "DEVICE_CODE_ISSUED_AT")
	private Date deviceCodeIssuedAt;
	@Column(name = "DEVICE_CODE_EXPIRES_AT")
	private Date deviceCodeExpiresAt;
	@Lob
	@Column(name = "DEVICE_CODE_METADATA", columnDefinition="BLOB")
	private byte[] deviceCodeMetadata;
}
