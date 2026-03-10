package com.pawsstay.identityservice.controller;

import com.pawsstay.identityservice.dto.UserResponse;
import com.pawsstay.identityservice.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.UUID;

@RestController
@RequestMapping("api/user")
@RequiredArgsConstructor
public class UserController {
    private final UserService userService;

    @GetMapping("{userId}")
    public ResponseEntity<UserResponse> userDetail(@PathVariable UUID userId){
        UserResponse userDetail = userService.getUserDetail(userId);
        return ResponseEntity.ok(userDetail);
    }

}
