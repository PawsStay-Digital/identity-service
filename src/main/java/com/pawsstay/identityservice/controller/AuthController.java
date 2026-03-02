package com.pawsstay.identityservice.controller;

import com.pawsstay.identityservice.dto.*;
import com.pawsstay.identityservice.service.AuthService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.UUID;


@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
@Slf4j
public class AuthController {
    private final AuthService authService;

    @PostMapping("/register")
    public ResponseEntity<RegisterResponse> register(@Valid @RequestBody RegisterRequest request) {
        log.info("user register email:{}, userName:{}", request.getEmail(), request.getUsername());
        return ResponseEntity.ok(authService.register(request));
    }

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@Valid @RequestBody LoginRequest request) {
        log.info("user login email:{}", request.getEmail());
        return ResponseEntity.ok(authService.login(request));
    }

    @PostMapping("/refresh")
    public ResponseEntity<AuthResponse> refreshToken(@Valid @RequestBody RefreshRequest request) {
        log.debug("refreshToken for: {}", request.getRefreshToken());
        return ResponseEntity.ok(authService.refreshToken(request));
    }

    @PostMapping("/update")
    public ResponseEntity<AuthResponse> updateProfile(@RequestHeader("X-User-Id") UUID userId,
                                                      @Valid @RequestBody UpdateUserRequest request) {
        log.info("user updateProfile email:{}, userName:{}", request.getEmail(), request.getUsername());
        return ResponseEntity.ok(authService.updateUserEmailAndUsername(userId, request));
    }


}
