package com.afromane.kms.dto;

import jakarta.validation.constraints.NotBlank;

/**
 * Objet de transfert de données (DTO) pour une demande de signature cryptographique.
 *
 * @param keyId      identifiant optionnel de la clé RSA souhaitée (si omis, la clé active est utilisée)
 * @param dataBase64 données brutes ou condensat à signer, encodé en chaîne Base64
 *
 * @author afromane
 * @version 1.0.0
 */
public record SignRequest(
    String keyId,
    @NotBlank(message = "Le payload Base64 ne doit pas être vide")
    String dataBase64
) {}
