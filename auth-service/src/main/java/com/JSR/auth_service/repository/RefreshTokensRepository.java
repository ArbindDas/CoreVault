package com.JSR.auth_service.repository;

import com.JSR.auth_service.entities.RefreshTokens;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;


@Repository
public interface RefreshTokensRepository extends JpaRepository<RefreshTokens ,Long> {
}
