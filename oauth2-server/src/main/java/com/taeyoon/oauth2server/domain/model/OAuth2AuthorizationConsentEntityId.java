package com.taeyoon.oauth2server.domain.model;

import java.io.Serial;
import java.io.Serializable;
import java.util.Objects;

import org.hibernate.Hibernate;

import jakarta.persistence.Column;
import jakarta.persistence.Embeddable;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
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
@Embeddable
public class OAuth2AuthorizationConsentEntityId implements Serializable {

	@Serial
	private static final long serialVersionUID = -425992677778323096L;

	@Column(name = "REGISTERED_CLIENT_ID")
	private String registeredClientId;
	@Column(name = "PRINCIPAL_NAME")
	private String principalName;

	@Override
	public boolean equals(Object o) {
		if (this == o)
			return true;
		if (o == null || Hibernate.getClass(this) != Hibernate.getClass(o))
			return false;
		OAuth2AuthorizationConsentEntityId that = (OAuth2AuthorizationConsentEntityId)o;
		return Objects.equals(registeredClientId, that.registeredClientId) && Objects.equals(
			principalName, that.principalName);
	}

	@Override
	public int hashCode() {
		return Objects.hash(registeredClientId, principalName);
	}
}
