package com.pawsstay.identityservice.service;

import com.pawsstay.identityservice.dto.*;
import com.pawsstay.identityservice.entity.RefreshToken;
import com.pawsstay.identityservice.entity.User;
import com.pawsstay.identityservice.entity.UserRole;
import com.pawsstay.identityservice.exception.ConflictException;
import com.pawsstay.identityservice.exception.UnauthorizedException;
import com.pawsstay.identityservice.repository.RefreshTokenRepository;
import com.pawsstay.identityservice.repository.UserRepository;
import com.pawsstay.identityservice.util.JwtUtils;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;


import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtils jwtUtils;
    private final RefreshTokenRepository refreshTokenRepository;
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
            cleanRefreshTokens(user);
            RefreshToken refreshToken = refreshTokenRepository.save(generateRefreshToken(user));
            return generateAuthResponse(user, refreshToken);
        } else {
            throw new UnauthorizedException("Invalid email or password");
        }
    }

    @Override
    @Transactional
    public AuthResponse refreshToken(RefreshRequest request) {
        RefreshToken oldToken = refreshTokenRepository.findRefreshTokenByToken(request.getRefreshToken())
                .orElseThrow(() -> new UnauthorizedException("refresh token not found"));

        if (oldToken.getExpiryDate().isBefore(Instant.now())) {
            refreshTokenRepository.delete(oldToken);
            throw new UnauthorizedException("Refresh Token Expired");
        }
        RefreshToken newToken = generateRefreshToken(oldToken.getUser());
        refreshTokenRepository.saveAndFlush(newToken);
        refreshTokenRepository.delete(oldToken);

        return generateAuthResponse(oldToken.getUser(), newToken);
    }

    @Override
    public void logout(String refreshToken) {

    }

    @Override
    @Transactional
    public AuthResponse updateUserEmailAndUsername(UUID id, UpdateUserRequest request) {
        User user = userRepository.findById(id)
                .orElseThrow(() -> new UnauthorizedException("user not found when update"));
        if (request.getEmail() != null && !user.getEmail().equals(request.getEmail())) {
            if (userRepository.existsByEmail(request.getEmail())) {
                log.info("email conflict :{}", request.getEmail());
                throw new ConflictException("email conflict");
            }
            user.setEmail(request.getEmail());
        }
        if (request.getUsername() != null && !request.getUsername().isBlank()) {
            user.setUsername(request.getUsername());
        }
        User savedUser = userRepository.saveAndFlush(user);
        log.info("update user success id:{}, email:{}, userName:{}", savedUser.getId(), savedUser.getEmail(),
                savedUser.getUsername());
        refreshTokenRepository.deleteAllByUser(savedUser);
        RefreshToken refreshToken = refreshTokenRepository.save(generateRefreshToken(user));
        return generateAuthResponse(savedUser, refreshToken);
    }

    private RegisterResponse map2RegisterResponse(User user) {
        return RegisterResponse.builder()
                .id(user.getId())
                .email(user.getEmail())
                .userName(user.getUsername())
                .role(user.getRole().toString())
                .createdAt(user.getCreatedAt())
                .build();
    }

    private User map2UserEntity(RegisterRequest request) {
        return User.builder()
                .email(request.getEmail())
                .role(UserRole.OWNER)
                .password(passwordEncoder.encode(request.getPassword()))
                .username(request.getUsername())
                .build();

    }

    private void cleanRefreshTokens(User user) {
        int MAX_REFRESH_TOKEN_AMOUNT = 5;
        if (refreshTokenRepository.countByUser(user) >= MAX_REFRESH_TOKEN_AMOUNT) {
            List<RefreshToken> refreshTokenList = refreshTokenRepository.findRefreshTokenByUserOrderByExpiryDateAsc(user);
            List<RefreshToken> toDelete = refreshTokenList.stream()
                    .limit(refreshTokenList.size() - MAX_REFRESH_TOKEN_AMOUNT)
                    .toList();
            refreshTokenRepository.deleteAll(toDelete);
        }
    }

    private RefreshToken generateRefreshToken(User user) {
        String refreshTokenString = UUID.randomUUID().toString();
        return RefreshToken.builder().token(refreshTokenString)
                .user(user)
                .expiryDate(Instant.now().plus(REFRESH_TOKEN_EXPIRATION, ChronoUnit.SECONDS))
                .build();

    }

    private AuthResponse generateAuthResponse(User user, RefreshToken refreshToken) {
        return AuthResponse.builder()
                .accessToken(jwtUtils.generateToken(user))
                .refreshToken(refreshToken.getToken())
                .userId(user.getId())
                .userName(user.getUsername())
                .email(user.getEmail())
                .expiresIn(SECRET_EXPIRATION)
                .refreshExpiresIn(REFRESH_TOKEN_EXPIRATION)
                .build();
    }
}
