package com.pawsstay.identityservice.service;

import com.pawsstay.identityservice.dto.UserResponse;

import java.util.UUID;

public interface UserService {
    UserResponse getUserDetail(UUID userId);
}
