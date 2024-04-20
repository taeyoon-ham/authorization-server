package com.taeyoon.oauth2server.infra.utils;

import java.util.Map;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;

public class ObjectMapperUtils {
	private static final ObjectMapper objectMapper = createObjectMapper();

	private static ObjectMapper createObjectMapper() {
		ObjectMapper mapper = new ObjectMapper();
		mapper.registerModule(new JavaTimeModule());
		mapper.disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
		return mapper;
	}

	// JSON 문자열을 Java 객체로 변환
	public static <T> T fromJson(String json, Class<T> valueType) {
		try {
			return objectMapper.readValue(json, valueType);
		} catch (JsonProcessingException e) {
			// 예외 처리 로직에 따라 적절히 변경
			throw new RuntimeException("Error converting JSON to object", e);
		}
	}

	public static <T> T fromJson(String json, TypeReference<T> typeReference) {
		try {
			return objectMapper.readValue(json, typeReference);
		} catch (JsonProcessingException e) {
			// 예외 처리 로직에 따라 적절히 변경
			throw new RuntimeException("Error converting JSON to object", e);
		}
	}

	public static Map<String, Object> parsingMapFromJson(String json) {
		return fromJson(json, new TypeReference<Map<String, Object>>() {
		});
	}

	// Java 객체를 JSON 문자열로 변환
	public static String toJson(Object value) {
		try {
			return objectMapper.writeValueAsString(value);
		} catch (JsonProcessingException e) {
			// 예외 처리 로직에 따라 적절히 변경
			throw new RuntimeException("Error converting object to JSON", e);
		}
	}

	// Java 객체 간의 깊은 복사 수행
	public static <T> T deepCopy(Object value, Class<T> valueType) {
		try {
			String json = objectMapper.writeValueAsString(value);
			return objectMapper.readValue(json, valueType);
		} catch (JsonProcessingException e) {
			// 예외 처리 로직에 따라 적절히 변경
			throw new RuntimeException("Error performing deep copy", e);
		}
	}
}
