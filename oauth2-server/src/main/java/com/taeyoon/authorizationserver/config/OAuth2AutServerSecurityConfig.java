package com.taeyoon.authorizationserver.config;/*
 * Copyright 2021 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Role;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.token.DelegatingOAuth2TokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.JwtGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2AccessTokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2RefreshTokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

/**
 * OAuth Authorization Server Configuration.
 *
 * @author Steve Riesenberg
 */
@Configuration
@EnableWebSecurity(debug = true)
public class OAuth2AutServerSecurityConfig {

	/**
	 * 인증서버를 위한 기본 구성
	 */
	@Bean
	@Order(Ordered.HIGHEST_PRECEDENCE)
	public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
		OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
		http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
			// .registeredClientRepository(registeredClientRepository) // 신규 및 기존 클라이언트를 관리하기 위한 RegisteredClientRepository( 필수 )입니다.
			// .authorizationServerSettings(authorizationServerSettings) // OAuth2 인증 서버에 대한 구성 설정을 사용자 정의하기 위한 AuthorizationServerSettings( 필수 )입니다.
			// .tokenGenerator(tokenGenerator) // OAuth2TokenGeneratorOAuth2 인증 서버에서 지원하는 토큰을 생성하기 위한 것입니다. code, access_token, refresh_token, id_token
			// .clientAuthentication(clientAuthentication -> { }) // OAuth2 클라이언트 인증을 위한 구성자입니다 . client_id, client_secret 을 추출하고 인증하는 역할. PasswordEncoder => BCryptPasswordEncoder
			// .authorizationEndpoint(authorizationEndpoint -> { }) // OAuth2 인증 엔드포인트 의 구성자입니다 . 인가코드 요청처리, 동의화면 제공 등.
			// .authorizationService(authorizationService) // OAuth2AuthorizationService 신규 및 기존 인증을 관리하기 위한 것입니다. (클라이언트 인증, 권한 부여 처리, 토큰 자체 검사, 토큰 취소, 동적 클라이언트 등록 등)
			// .authorizationConsentService(authorizationConsentService) // OAuth2AuthorizationConsentService 신규 및 기존 승인 동의를 관리하기 위한 것입니다.
			// .deviceAuthorizationEndpoint(deviceAuthorizationEndpoint -> { }) // OAuth2 장치 인증 엔드포인트 의 구성자입니다 .
			// .deviceVerificationEndpoint(deviceVerificationEndpoint -> { }) // OAuth2 장치 확인 엔드포인트 의 구성자입니다 .
			// .tokenEndpoint(tokenEndpoint -> { }) // OAuth2 토큰 엔드포인트 의 구성자입니다 . accessToken 요청 정보 추출 (인가코드 등), 인증, 발급하는 역할
			// .tokenIntrospectionEndpoint(tokenIntrospectionEndpoint -> { } ) // OAuth2 Token Introspection 엔드포인트 의 구성자입니다 . 발급한 토큰 검사
			// .tokenRevocationEndpoint(tokenRevocationEndpoint -> { }) // OAuth2 토큰 해지 엔드포인트 의 구성자입니다 .
			// .authorizationServerMetadataEndpoint(authorizationServerMetadataEndpoint -> { }) // OAuth2 인증 서버 메타데이터 엔드포인트의 구성자입니다 .
			// .oidc(oidc -> oidc
				// .providerConfigurationEndpoint(providerConfigurationEndpoint -> { }) // OpenID Connect 1.0 공급자 구성 엔드포인트의 구성자입니다 .
				// .logoutEndpoint(logoutEndpoint -> { }) // OpenID Connect 1.0 로그아웃 엔드포인트 의 구성자입니다 .
				// .userInfoEndpoint(userInfoEndpoint -> { }) // OpenID Connect 1.0 UserInfo 엔드포인트 의 구성자입니다 .
				// .clientRegistrationEndpoint(clientRegistrationEndpoint -> { }) // OpenID Connect 1.0 클라이언트 등록 엔드포인트 의 구성자입니다 .
			.oidc(Customizer.withDefaults());
		http
			// .exceptionHandling((exceptions) -> exceptions
			// 	.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login"))
			// )
			.exceptionHandling((exceptions) -> exceptions
				.defaultAuthenticationEntryPointFor(
					new LoginUrlAuthenticationEntryPoint("/login"),
					new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
				)
			)
			// Accept access tokens for User Info and/or Client Registration
			.oauth2ResourceServer((resourceServer) -> resourceServer
				.jwt(Customizer.withDefaults()));

		return http.build();
	}

	// Resource Owner 인증을 위한 로그인 페이지 설정
	@Bean
	@Order(2)
	public SecurityFilterChain standardSecurityFilterChain(HttpSecurity http) throws Exception {
		// @formatter:off
		http
			.authorizeHttpRequests(authorizeRequests ->
				authorizeRequests
					.requestMatchers(
						AntPathRequestMatcher.antMatcher("/h2-console/**")
					).permitAll()
					.requestMatchers(
						AntPathRequestMatcher.antMatcher("/**")
					).authenticated()
			)
			.headers(headers -> headers.frameOptions(HeadersConfigurer.FrameOptionsConfig::disable))
			.csrf(csrf -> csrf.ignoringRequestMatchers(("/h2-console/**")))
			.formLogin(Customizer.withDefaults());
		// @formatter:on

		return http.build();
	}

	@Bean
	public WebSecurityCustomizer webSecurityCustomizer() {
		// 정적 리소스 spring security 대상에서 제외
		return (web) -> web
			.ignoring()
			.requestMatchers(
				AntPathRequestMatcher.antMatcher("/chrome.css.map")
			)
			.requestMatchers(
				AntPathRequestMatcher.antMatcher("/h2-console")
			)
			.requestMatchers(
				PathRequest.toStaticResources().atCommonLocations()
			);
	}


	// 이는 OAuth2AuthorizationService 새 권한이 저장되고 기존 권한이 쿼리되는 중앙 구성 요소입니다.
	// 이는 특정 프로토콜 흐름(예: 클라이언트 인증, 권한 부여 처리, 토큰 자체 검사, 토큰 취소, 동적 클라이언트 등록 등)을 따를 때 다른 component 에서 사용됩니다.
	// @Bean
	// public OAuth2AuthorizationService authorizationService() {
	// 	return new InMemoryOAuth2AuthorizationService();
	// }


	// 이는 OAuth2AuthorizationConsentService 새로운 승인 동의가 저장되고 기존 승인 동의가 쿼리되는 중앙 component 입니다.
	// 주로 OAuth2 인증 요청 흐름(예: 승인)을 구현하는 component 에서 사용됩니다 authorization_code.
	// @Bean
	// public OAuth2AuthorizationConsentService authorizationConsentService() {
	//
	// 	String registeredClientId = "f6dcdbe4-454f-49fa-8ce0-575b9bca2f6f";
	// 	String principalName = "user";
	// 	Consumer<Set<GrantedAuthority>> authorities = list -> {
	// 		list.add(new SimpleGrantedAuthority("SCOPE_"+OidcScopes.OPENID));
	// 		list.add(new SimpleGrantedAuthority("SCOPE_"+OidcScopes.PROFILE));
	// 		list.add(new SimpleGrantedAuthority("SCOPE_"+OidcScopes.ADDRESS));
	// 		list.add(new SimpleGrantedAuthority("SCOPE_"+OidcScopes.EMAIL));
	// 		list.add(new SimpleGrantedAuthority("SCOPE_"+OidcScopes.PHONE));
	// 	};
	//
	// 	return new InMemoryOAuth2AuthorizationConsentService(OAuth2AuthorizationConsent.withId(registeredClientId, principalName).authorities(authorities).build());
	// }

	// AuthorizationServerSettingsOAuth2 인증 서버에 대한 구성 설정이 포함되어 있습니다.
	// 이는 URI프로토콜 끝점과 발급자 식별자를 지정합니다 . URI프로토콜 끝점의 기본값 은 다음과 같습니다.
	@Bean
	public AuthorizationServerSettings authorizationServerSettings() {
		return AuthorizationServerSettings.builder()
			.issuer("http://localhost:9000")
			.authorizationEndpoint("/oauth2/v1/authorize")
			.deviceAuthorizationEndpoint("/oauth2/v1/device_authorization")
			.deviceVerificationEndpoint("/oauth2/v1/device_verification")
			.tokenEndpoint("/oauth2/v1/token")
			.tokenIntrospectionEndpoint("/oauth2/v1/introspect")
			.tokenRevocationEndpoint("/oauth2/v1/revoke")
			.jwkSetEndpoint("/oauth2/v1/jwks")
			.oidcLogoutEndpoint("/connect/v1/logout")
			.oidcUserInfoEndpoint("/connect/v1/userinfo")
			.oidcClientRegistrationEndpoint("/connect/v1/register")
			.build();
	}

	// @Bean
	// public OAuth2TokenGenerator<?> tokenGenerator() {
	// 	JwtEncoder jwtEncoder = new NimbusJwtEncoder(jwkSource(generateRsaKey()));
	// 	JwtGenerator jwtGenerator = new JwtGenerator(jwtEncoder);
	// 	OAuth2AccessTokenGenerator accessTokenGenerator = new OAuth2AccessTokenGenerator();
	// 	OAuth2RefreshTokenGenerator refreshTokenGenerator = new OAuth2RefreshTokenGenerator();
	// 	return new DelegatingOAuth2TokenGenerator(
	// 		jwtGenerator, accessTokenGenerator, refreshTokenGenerator);
	// }


	// Resource Owner in memory
	@Bean
	public UserDetailsService userDetailsService() {
		// @formatter:off
		UserDetails userDetails = User.withDefaultPasswordEncoder()
			.username("user")
			.password("password")
			.roles("USER")
			.build();
		// @formatter:on

		return new InMemoryUserDetailsManager(userDetails);
	}


	// 이는 RegisteredClientRepository 새 클라이언트를 등록하고 기존 클라이언트를 쿼리할 수 있는 중앙 구성 요소입니다.
	// 클라이언트 인증, 권한 부여 처리, 토큰 검사, 동적 클라이언트 등록 등과 같은 특정 프로토콜 흐름을 따를 때 다른 구성 요소에서 사용됩니다.
	@Bean
	public RegisteredClientRepository registeredClientRepository() {
		RegisteredClient oidcClient = RegisteredClient.withId(UUID.randomUUID().toString())
			.clientId("oidc-client")
			.clientSecret("{noop}secret")
			.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
			.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
			.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
			.redirectUri("http://localhost/authorized")
			.postLogoutRedirectUri("http://127.0.0.1:8080/")
			.scope(OidcScopes.OPENID)
			.scope(OidcScopes.PROFILE)
			.clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
			.build();

		return new InMemoryRegisteredClientRepository(oidcClient);
	}


	// 액세스 토큰 서명을 위한 인스턴스입니다 .
	@Bean
	public JWKSource<SecurityContext> jwkSource() {
		KeyPair keyPair = generateRsaKey();
		RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
		RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
		RSAKey rsaKey = new RSAKey.Builder(publicKey)
			.privateKey(privateKey)
			.keyID(UUID.randomUUID().toString())
			.build();
		JWKSet jwkSet = new JWKSet(rsaKey);
		return new ImmutableJWKSet<>(jwkSet);
	}

	// 위 항목 을 생성하는 데 사용된 시작 시 생성된 키가 있는 인스턴스입니다
	@Bean
	@Role(BeanDefinition.ROLE_INFRASTRUCTURE)
	private static KeyPair generateRsaKey() {
		KeyPair keyPair;
		try {
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
			keyPairGenerator.initialize(2048);
			keyPair = keyPairGenerator.generateKeyPair();
		}
		catch (Exception ex) {
			throw new IllegalStateException(ex);
		}
		return keyPair;
	}

	// 서명된 액세스 토큰을 디코딩하기 위한 인스턴스입니다 .
	@Bean
	public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
		return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
	}
}