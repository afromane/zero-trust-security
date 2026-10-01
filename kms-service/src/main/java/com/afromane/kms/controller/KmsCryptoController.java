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

@RestController
@RequestMapping("/api/v1/kms")
public class KmsCryptoController {

    private final KeyManagementService keyManagementService;

    public KmsCryptoController(KeyManagementService keyManagementService) {
        this.keyManagementService = keyManagementService;
    }

    @PostMapping("/sign")
    public ResponseEntity<SignResponse> sign(@Valid @RequestBody SignRequest request) {
        byte[] payloadBytes = Base64.getDecoder().decode(request.dataBase64());
        SignResponse response = keyManagementService.sign(request.keyId(), payloadBytes);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/verify")
    public ResponseEntity<VerifyResponse> verify(@Valid @RequestBody VerifyRequest request) {
        byte[] payloadBytes = Base64.getDecoder().decode(request.dataBase64());
        byte[] signatureBytes = Base64.getDecoder().decode(request.signatureBase64());
        VerifyResponse response = keyManagementService.verify(request.keyId(), payloadBytes, signatureBytes);
        return ResponseEntity.ok(response);
    }

    @GetMapping("/active-key-id")
    public ResponseEntity<String> getActiveKeyId() {
        return ResponseEntity.ok(keyManagementService.getActiveKeyId());
    }
}
