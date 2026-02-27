package com.pawsstay.identityservice.service;

import com.pawsstay.identityservice.dto.*;
import com.pawsstay.identityservice.entity.User;
import com.pawsstay.identityservice.entity.UserRole;
import com.pawsstay.identityservice.exception.ConflictException;
import com.pawsstay.identityservice.exception.UnauthorizedException;
import com.pawsstay.identityservice.repository.UserRepository;
import com.pawsstay.identityservice.util.JwtUtils;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService{
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtils jwtUtils;
    @Value("${app.jwt.expiration}")
    private Long SECRET_EXPIRATION;
    @Value("${app.refresh-token.expiration}")
    private Long REFRESH_TOKEN_EXPIRATION;
    @Override
    @Transactional
    public RegisterResponse register(RegisterRequest request) {
        if (userRepository.existsByEmail(request.getEmail())) {
            log.warn("email conflict :{}", request.getEmail());
            throw new ConflictException("email conflict");
        }
        User user = map2UserEntity(request);
        User savedUser = userRepository.saveAndFlush(user);
        log.info("save user success id:{}, email:{}, userName:{}", user.getId(), user.getEmail(), user.getUsername());
        return map2RegisterResponse(savedUser);
    }

    @Override
    @Transactional
    public AuthResponse login(LoginRequest request) {
        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new UnauthorizedException("Invalid email or password"));
        if (passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            String token = jwtUtils.generateToken(user);
            String refreshToken = UUID.randomUUID().toString();
            return AuthResponse.builder()
                    .accessToken(token)
                    .refreshToken(refreshToken)
                    .userId(user.getId())
                    .userName(user.getUsername())
                    .email(user.getEmail())
                    .expiresIn(SECRET_EXPIRATION)
                    .refreshExpiresIn(REFRESH_TOKEN_EXPIRATION)
                    .build();
        } else {
            throw new UnauthorizedException("Invalid email or password");
        }
    }

    @Override
    public AuthResponse refreshToken(String refreshToken) {
        return null;
    }

    @Override
    public void logout(String refreshToken) {

    }

    @Override
    @Transactional
    public RegisterResponse updateUserEmailAndUsername(UpdateUserRequest request) {
        if (userRepository.existsByEmail(request.getEmail())) {
            log.info("email conflict :{}", request.getEmail());
            throw new UnauthorizedException("email conflict");
        }
        User user = userRepository.findById(UUID.fromString(request.getId()))
                .orElseThrow(() -> new UnauthorizedException("user not found"));
        user.setEmail(request.getEmail());
        user.setUsername(request.getUsername());
        user = userRepository.save(user);

        return map2RegisterResponse(user);
    }

    private RegisterResponse map2RegisterResponse(User user){
        return RegisterResponse.builder()
                .id(user.getId())
                .email(user.getEmail())
                .userName(user.getUsername())
                .role(user.getRole().toString())
                .createdAt(user.getCreatedAt())
                .build();
    }
    private User map2UserEntity(RegisterRequest request){
        return User.builder()
                    .email(request.getEmail())
                    .role(UserRole.OWNER)
                    .password(passwordEncoder.encode(request.getPassword()))
                    .username(request.getUsername())
                    .build();

    }
}
