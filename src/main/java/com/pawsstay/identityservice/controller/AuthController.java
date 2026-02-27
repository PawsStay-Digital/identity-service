package com.pawsstay.identityservice.controller;

import com.pawsstay.identityservice.dto.LoginRequest;
import com.pawsstay.identityservice.dto.RegisterRequest;
import com.pawsstay.identityservice.dto.RegisterResponse;
import com.pawsstay.identityservice.service.AuthService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;


@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
@Slf4j
public class AuthController {
    private final AuthService authService;

    @PostMapping("/register")
    public ResponseEntity<RegisterResponse> register(@RequestBody RegisterRequest request) {
        log.info("user register email:{}, userName:{}", request.getEmail(), request.getUsername());
        return ResponseEntity.ok(authService.register(request));
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest request) {
        log.info("user login email:{}", request.getEmail());
        return ResponseEntity.ok(authService.login(request));
    }
}
