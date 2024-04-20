package com.taeyoon.oauth2server.infra.utils;

import java.nio.charset.StandardCharsets;

public class StringUtils extends org.springframework.util.StringUtils {

	public static String byteToString(byte[] str) {
		if (str == null) return null;
		return new String(str, StandardCharsets.UTF_8);
	}
}
