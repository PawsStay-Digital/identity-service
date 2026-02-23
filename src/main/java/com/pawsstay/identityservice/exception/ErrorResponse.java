package com.pawsstay.identityservice.exception;

public record ErrorResponse(int status, String message, long timestamp){
}
