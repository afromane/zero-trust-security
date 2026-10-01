package com.afromane.kms.controller;

import com.afromane.kms.service.KeyManagementService;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
public class JwksController {

    private final KeyManagementService keyManagementService;

    public JwksController(KeyManagementService keyManagementService) {
        this.keyManagementService = keyManagementService;
    }

    @GetMapping(value = "/.well-known/jwks.json", produces = MediaType.APPLICATION_JSON_VALUE)
    public Map<String, Object> getJwks() {
        return keyManagementService.getJwkSet().toJSONObject();
    }
}
