package com.taeyoon.authorizationserver.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class LoginController {
	@PostMapping("/login")
	public void login(@RequestParam("username") String username, @RequestParam("password") String password) {
		System.out.println("username: " + username + " password: " + password);
	}
}
