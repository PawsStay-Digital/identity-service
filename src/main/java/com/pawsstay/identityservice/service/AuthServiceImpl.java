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
public class AuthServiceImpl implements AuthService{
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
            return generateAuthResponse(user,refreshToken);
        } else {
            throw new UnauthorizedException("Invalid email or password");
        }
    }

    @Override
    @Transactional
    public AuthResponse refreshToken(String refreshToken) {
        RefreshToken refreshTokenData = refreshTokenRepository.findRefreshTokenByToken(refreshToken)
                .orElseThrow(() -> new UnauthorizedException("refresh token not found"));
        User user = refreshTokenData.getUser();
        refreshTokenRepository.saveAndFlush(generateRefreshToken(user));
        return generateAuthResponse(user,refreshTokenData);
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
        userRepository.saveAndFlush(user);

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

    private void cleanRefreshTokens(User user){
        List<RefreshToken> refreshTokenList = refreshTokenRepository.findRefreshTokenByUserOrderByExpiryDateAsc(user);
        if(refreshTokenList.size() > 10){
            int numberToRemove = refreshTokenList.size() - 10;
            List<RefreshToken> toDelete = refreshTokenList.stream()
                    .limit(numberToRemove)
                    .toList();
            refreshTokenRepository.deleteAll(toDelete);
        }
    }
    private RefreshToken generateRefreshToken(User user){
        String refreshTokenString = UUID.randomUUID().toString();
        return RefreshToken.builder().token(refreshTokenString)
                .user(user)
                .expiryDate(Instant.now().plus(REFRESH_TOKEN_EXPIRATION, ChronoUnit.SECONDS))
                .build();

    }

    private AuthResponse generateAuthResponse(User user, RefreshToken refreshToken){
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
