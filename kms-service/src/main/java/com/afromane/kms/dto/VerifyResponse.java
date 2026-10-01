package com.afromane.kms.dto;

public record VerifyResponse(
    String keyId,
    boolean valid,
    String message
) {}
