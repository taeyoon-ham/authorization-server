package com.taeyoon.oauth2server.infra.config;

import java.util.Locale;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.LocaleResolver;
import org.springframework.web.servlet.i18n.AcceptHeaderLocaleResolver;

@Configuration
public class SpringConfig {

	@Bean
	public LocaleResolver localeResolver() {
		// Accept-Language 헤더를 기반으로 로케일을 결정하는 LocaleResolver
		AcceptHeaderLocaleResolver localeResolver = new AcceptHeaderLocaleResolver();
		// 기본 로케일 설정 (선택 사항)
		localeResolver.setDefaultLocale(Locale.ENGLISH);
		return localeResolver;
	}
}
