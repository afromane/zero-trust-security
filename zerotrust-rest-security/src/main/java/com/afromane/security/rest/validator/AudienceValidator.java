package com.afromane.security.rest.validator;

import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.List;

/**
 * Validateur de jeton JWT appliquant le principe Zero Trust d'isolation d'audience.
 * <p>
 * Ce composant vérifie que la liste des destinataires légitimes (claim {@code aud}) du jeton JWT
 * contient impérativement le nom du microservice courant.
 * </p>
 * <p>
 * <b>Objectif de sécurité :</b> Si un token émis légitimement pour le service A est intercepté ou réutilisé
 * pour attaquer le service B, cette vérification bloque immédiatement l'accès, empêchant les attaques
 * par déplacement latéral et par rejeu de jetons (*Token Replay Attacks*).
 * </p>
 *
 * @author afromane
 * @version 1.0.0
 */
public class AudienceValidator implements OAuth2TokenValidator<Jwt> {

    private final String expectedAudience;

    /**
     * Initialise le validateur avec l'audience attendue pour ce microservice.
     *
     * @param expectedAudience nom de l'audience obligatoire (ex: {@code order-service})
     */
    public AudienceValidator(String expectedAudience) {
        this.expectedAudience = expectedAudience;
    }

    /**
     * Valide le claim {@code aud} du jeton JWT fourni.
     *
     * @param jwt jeton JWT décodé à inspecter
     * @return {@link OAuth2TokenValidatorResult#success()} si l'audience correspond,
     *         ou {@link OAuth2TokenValidatorResult#failure(OAuth2Error)} si le jeton n'est pas destiné à ce service
     */
    @Override
    public OAuth2TokenValidatorResult validate(Jwt jwt) {
        if (expectedAudience == null || expectedAudience.isBlank()) {
            return OAuth2TokenValidatorResult.success();
        }

        List<String> audiences = jwt.getAudience();
        if (audiences != null && audiences.contains(expectedAudience)) {
            return OAuth2TokenValidatorResult.success();
        }

        OAuth2Error error = new OAuth2Error(
                "invalid_token",
                "Le token n'est pas destiné à ce service (Audience attendue: " + expectedAudience + ")",
                null
        );
        return OAuth2TokenValidatorResult.failure(error);
    }
}
