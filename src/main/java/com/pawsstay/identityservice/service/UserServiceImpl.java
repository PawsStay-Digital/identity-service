package com.pawsstay.identityservice.service;

import com.pawsstay.identityservice.dto.UserResponse;
import com.pawsstay.identityservice.entity.User;
import com.pawsstay.identityservice.exception.UnauthorizedException;
import com.pawsstay.identityservice.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.UUID;

@Service
@Slf4j
@RequiredArgsConstructor
public class UserServiceImpl implements UserService{
    private final UserRepository userRepository;
    @Override
    public UserResponse getUserDetail(UUID userId) {
        User user = userRepository.findById(userId).orElseThrow(() ->
                new UnauthorizedException("user not found"));

        return map2UserResponse(user);
    }

    private UserResponse map2UserResponse(User user){
        return UserResponse.builder().userId(user.getId().toString())
                .username(user.getUsername()).email(user.getEmail()).build();
    }
}
