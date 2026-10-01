package com.afromane.kms.dto;

/**
 * Objet de transfert de données (DTO) retourné suite à la vérification d'une signature.
 *
 * @param keyId   identifiant de la clé utilisée pour la vérification
 * @param valid   {@code true} si la signature est intègre et correspond aux données, {@code false} sinon
 * @param message message explicatif du résultat du contrôle
 *
 * @author afromane
 * @version 1.0.0
 */
public record VerifyResponse(
    String keyId,
    boolean valid,
    String message
) {}
