package com.afromane.kms.dto;

import jakarta.validation.constraints.NotBlank;

/**
 * Objet de transfert de données (DTO) pour une demande de vérification de signature.
 *
 * @param keyId           identifiant de la clé RSA ayant servi à la signature
 * @param dataBase64      données originales ayant été signées, encodées en Base64
 * @param signatureBase64 signature à vérifier, encodée en Base64
 *
 * @author afromane
 * @version 1.0.0
 */
public record VerifyRequest(
    String keyId,
    @NotBlank String dataBase64,
    @NotBlank String signatureBase64
) {}
