package com.afromane.kms.controller;

import com.afromane.kms.service.KeyManagementService;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * Contrôleur REST publiant l'ensemble des clés publiques RSA actives au format standard JWKS (RFC 7517).
 * <p>
 * Ce point de terminaison est interrogé par :
 * <ul>
 *   <li>Les microservices Web (via le starter {@code zerotrust-rest-security}) pour valider les tokens JWT entrants.</li>
 *   <li>Les consommateurs Kafka (via le starter {@code zerotrust-kafka-signing}) pour vérifier les signatures de messages.</li>
 * </ul>
 * </p>
 *
 * @author afromane
 * @version 1.0.0
 */
@RestController
public class JwksController {

    private final KeyManagementService keyManagementService;

    /**
     * Construit le contrôleur JWKS avec le service de gestion des clés.
     *
     * @param keyManagementService service cryptographique
     */
    public JwksController(KeyManagementService keyManagementService) {
        this.keyManagementService = keyManagementService;
    }

    /**
     * Expose le trousseau de clés publiques (JSON Web Key Set).
     *
     * @return map représentant le document JSON standard contenant le tableau {@code keys}
     */
    @GetMapping(value = "/.well-known/jwks.json", produces = MediaType.APPLICATION_JSON_VALUE)
    public Map<String, Object> getJwks() {
        return keyManagementService.getJwkSet().toJSONObject();
    }
}
