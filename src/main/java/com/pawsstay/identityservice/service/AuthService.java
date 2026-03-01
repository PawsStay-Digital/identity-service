package com.pawsstay.identityservice.service;

import com.pawsstay.identityservice.dto.*;

public interface AuthService {
    RegisterResponse register(RegisterRequest request);
    AuthResponse login(LoginRequest request);
    AuthResponse refreshToken(RefreshRequest request);
    void logout(String refreshToken);
    RegisterResponse updateUserEmailAndUsername(UpdateUserRequest request);

}
