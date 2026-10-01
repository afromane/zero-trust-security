package com.afromane.kms.controller;

import com.afromane.kms.dto.SignRequest;
import com.afromane.kms.dto.SignResponse;
import com.afromane.kms.dto.VerifyRequest;
import com.afromane.kms.dto.VerifyResponse;
import com.afromane.kms.service.KeyManagementService;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Base64;

/**
 * Contrôleur REST exposant les opérations cryptographiques du KMS.
 * <p>
 * Permet aux microservices autorisés de demander la signature de charges utiles (payloads)
 * ou de vérifier la validité d'une signature sans jamais avoir accès direct à la clé privée RSA.
 * </p>
 *
 * @author afromane
 * @version 1.0.0
 */
@RestController
@RequestMapping("/api/v1/kms")
public class KmsCryptoController {

    private final KeyManagementService keyManagementService;

    /**
     * Construit le contrôleur avec le service de gestion des clés.
     *
     * @param keyManagementService service cryptographique sous-jacent
     */
    public KmsCryptoController(KeyManagementService keyManagementService) {
        this.keyManagementService = keyManagementService;
    }

    /**
     * Signe un contenu binaire encodé en Base64 à l'aide de la clé privée active.
     *
     * @param request objet contenant les données Base64 à signer et optionnellement le keyId
     * @return {@link ResponseEntity} contenant le {@link SignResponse} avec la signature Base64
     */
    @PostMapping("/sign")
    public ResponseEntity<SignResponse> sign(@Valid @RequestBody SignRequest request) {
        byte[] payloadBytes = Base64.getDecoder().decode(request.dataBase64());
        SignResponse response = keyManagementService.sign(request.keyId(), payloadBytes);
        return ResponseEntity.ok(response);
    }

    /**
     * Vérifie si une signature correspond aux données d'origine et à la clé publique associée.
     *
     * @param request objet contenant les données d'origine et la signature Base64
     * @return {@link ResponseEntity} contenant le {@link VerifyResponse} avec le verdict booléen
     */
    @PostMapping("/verify")
    public ResponseEntity<VerifyResponse> verify(@Valid @RequestBody VerifyRequest request) {
        byte[] payloadBytes = Base64.getDecoder().decode(request.dataBase64());
        byte[] signatureBytes = Base64.getDecoder().decode(request.signatureBase64());
        VerifyResponse response = keyManagementService.verify(request.keyId(), payloadBytes, signatureBytes);
        return ResponseEntity.ok(response);
    }

    /**
     * Renvoie l'identifiant de la clé de signature actuellement active.
     *
     * @return {@link ResponseEntity} avec la chaîne représentant le keyId
     */
    @GetMapping("/active-key-id")
    public ResponseEntity<String> getActiveKeyId() {
        return ResponseEntity.ok(keyManagementService.getActiveKeyId());
    }
}
