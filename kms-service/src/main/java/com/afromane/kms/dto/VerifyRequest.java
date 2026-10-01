package com.afromane.kms.dto;

import jakarta.validation.constraints.NotBlank;

public record VerifyRequest(
    String keyId,
    @NotBlank String dataBase64,
    @NotBlank String signatureBase64
) {}
