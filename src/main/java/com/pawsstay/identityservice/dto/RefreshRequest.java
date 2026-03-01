package com.pawsstay.identityservice.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class RefreshRequest {
    @NotBlank(message = "refreshToken can not be blank")
    private String refreshToken;
}
