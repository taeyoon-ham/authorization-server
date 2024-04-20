package com.taeyoon.oauth2server.application.dto;

import java.io.Serializable;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Builder
@NoArgsConstructor
@AllArgsConstructor
@Getter
@Setter
public class UserInfo implements Serializable {
	private String firstName;
	private String lastName;
	private String countryCode;
	private String telNo;
}
