package com.afromane.kms.dto;

import jakarta.validation.constraints.NotBlank;

public record SignRequest(
    String keyId,
    @NotBlank(message = "Le payload Base64 ne doit pas être vide")
    String dataBase64
) {}
