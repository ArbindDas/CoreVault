package com.JSR.auth_service.repository;

import com.JSR.auth_service.entities.Permissions;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface PermissionsRepository extends JpaRepository<Permissions , Long> {
}
