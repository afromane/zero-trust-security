package com.afromane.kms.repository;

import com.afromane.kms.model.KeyEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

/**
 * Interface d'accès aux données (Spring Data JPA) pour les clés cryptographiques.
 * <p>
 * Fournit les opérations CRUD ainsi que des requêtes spécifiques pour rechercher une clé par son
 * identifiant fonctionnel ou récupérer la dernière clé active pour les signatures.
 * </p>
 *
 * @author afromane
 * @version 1.0.0
 */
@Repository
public interface KeyRepository extends JpaRepository<KeyEntity, Long> {

    /**
     * Recherche une clé par son identifiant unique.
     *
     * @param keyId alias ou identifiant de la clé (ex: {@code zerotrust-master-key-v1})
     * @return un {@link Optional} contenant l'entité si trouvée
     */
    Optional<KeyEntity> findByKeyId(String keyId);

    /**
     * Récupère la clé active la plus récente, ordonnée par date de création décroissante.
     * Utilisée pour charger la clé de signature active lors du démarrage du microservice.
     *
     * @return un {@link Optional} contenant la clé active courante
     */
    Optional<KeyEntity> findFirstByActiveTrueOrderByCreatedAtDesc();

    /**
     * Récupère l'ensemble des clés marquées comme actives (pour publication dans le JWKS).
     *
     * @return liste des clés actives
     */
    List<KeyEntity> findAllByActiveTrue();
}
