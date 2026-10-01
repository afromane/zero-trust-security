package com.afromane.kms;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Point d'entrée principal du microservice KMS (Key Management Service) autonome.
 * <p>
 * Ce service assure la gestion du cycle de vie des clés cryptographiques asymétriques (RSA),
 * leur persistance sécurisée dans une base H2 scellée par l'algorithme AES-256 au repos,
 * ainsi que leur maintien en mémoire vive (RAM) pour des opérations de signature à très faible latence.
 * </p>
 *
 * @author afromane
 * @version 1.0.0
 */
@SpringBootApplication
public class KmsApplication {

    /**
     * Lance l'application Spring Boot du service KMS.
     *
     * @param args arguments de la ligne de commande
     */
    public static void main(String[] args) {
        SpringApplication.run(KmsApplication.class, args);
    }
}
