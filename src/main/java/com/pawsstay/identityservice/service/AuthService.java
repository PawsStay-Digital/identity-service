package com.pawsstay.identityservice.service;

import com.pawsstay.identityservice.dto.*;

import java.util.UUID;

public interface AuthService {
    RegisterResponse register(RegisterRequest request);

    AuthResponse login(LoginRequest request);

    AuthResponse refreshToken(RefreshRequest request);

    void logout(String refreshToken);

    AuthResponse updateUserEmailAndUsername(UUID id, UpdateUserRequest request);

}
