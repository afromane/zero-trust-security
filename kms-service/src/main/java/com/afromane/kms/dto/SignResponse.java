package com.afromane.kms.dto;

/**
 * Objet de transfert de données (DTO) retourné après une signature cryptographique réussie.
 *
 * @param keyId           identifiant de la clé RSA utilisée pour la signature
 * @param algorithm       nom de l'algorithme cryptographique appliqué (ex: {@code SHA256withRSA})
 * @param signatureBase64 signature numérique résultante, encodée en chaîne Base64
 *
 * @author afromane
 * @version 1.0.0
 */
public record SignResponse(
    String keyId,
    String algorithm,
    String signatureBase64
) {}
