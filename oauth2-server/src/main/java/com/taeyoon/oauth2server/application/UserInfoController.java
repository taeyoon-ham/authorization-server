package com.taeyoon.oauth2server.application;

import java.util.HashMap;
import java.util.Map;

import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import com.taeyoon.oauth2server.application.dto.UserInfo;

import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;

@RestController
@Slf4j
public class UserInfoController {
	@GetMapping(value = "/connect/userinfo", produces = MediaType.APPLICATION_JSON_VALUE)
	public ResponseEntity<Map<String, Object>> userInfo() {
		Map<String, Object> res = new HashMap<>();
		res.put("id", UserInfo.builder()
			.countryCode("+81")
			.telNo("01011112222")
			.firstName("길동")
			.lastName("홍")
			.build());
		return ResponseEntity.status(HttpServletResponse.SC_OK)
			.header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
			.body(res);
	}
}
