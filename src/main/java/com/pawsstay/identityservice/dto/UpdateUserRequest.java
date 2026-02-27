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
public class UpdateUserRequest {
    @NotBlank(message = "Email can not be blank")
    private String id;
    @NotBlank(message = "Email can not be blank")
    @Email(message = "invalid Email format")
    private String email;
    @NotBlank(message = "username can not be blank")
    private String username;

}
