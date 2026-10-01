package com.afromane.kms.repository;

import com.afromane.kms.model.KeyEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface KeyRepository extends JpaRepository<KeyEntity, Long> {

    Optional<KeyEntity> findByKeyId(String keyId);

    Optional<KeyEntity> findFirstByActiveTrueOrderByCreatedAtDesc();

    List<KeyEntity> findAllByActiveTrue();
}
