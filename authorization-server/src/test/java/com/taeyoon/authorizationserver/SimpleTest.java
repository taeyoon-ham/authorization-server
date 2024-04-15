package com.taeyoon.authorizationserver;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import org.junit.jupiter.api.Test;


public class SimpleTest {

	private static final String CLIENT_ID = "messaging-client";

	private static final String CLIENT_SECRET = "secret";
	@Test
	void test() {
		byte[] toEncode = (CLIENT_ID + ":" + CLIENT_SECRET).getBytes(StandardCharsets.UTF_8);
		String var10001 = new String(Base64.getEncoder().encode(toEncode));
		System.out.println(var10001);
	}
}
