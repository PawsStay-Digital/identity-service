package com.pawsstay.identityservice.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class LoginRequest {
    @NotBlank(message = "Email can not be blank")
    @Email(message = "invalid Email format")
    private String email;

    @NotBlank(message = "password can not be blank")
    @Size(min = 6, message = "password min size 6")
    private String password;
}
