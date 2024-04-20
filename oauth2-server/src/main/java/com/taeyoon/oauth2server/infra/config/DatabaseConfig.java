package com.taeyoon.oauth2server.infra.config;

import javax.sql.DataSource;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.core.env.Environment;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.transaction.annotation.EnableTransactionManagement;

import lombok.RequiredArgsConstructor;

@Configuration
@RequiredArgsConstructor
@EnableTransactionManagement
public class DatabaseConfig {
	private final Environment env;

	@Primary
	@Bean
	public DataSource andalosDataSource() {
		DriverManagerDataSource dataSource = new DriverManagerDataSource();
		dataSource.setDriverClassName(env.getProperty("spring.datasource.andalos.driver-class-name"));
		dataSource.setUrl(env.getProperty("spring.datasource.andalos.jdbc-url"));
		dataSource.setUsername(env.getProperty("spring.datasource.andalos.username"));
		dataSource.setPassword(env.getProperty("spring.datasource.andalos.password"));
		return dataSource;
	}
}
