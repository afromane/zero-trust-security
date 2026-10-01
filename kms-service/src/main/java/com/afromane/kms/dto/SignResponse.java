package com.afromane.kms.dto;

public record SignResponse(
    String keyId,
    String algorithm,
    String signatureBase64
) {}
