package com.JSR.auth_service.repository;

import com.JSR.auth_service.entities.Roles;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;


@Repository
public interface RolesRepository extends JpaRepository<Roles , Long> {

    Optional<Roles>findByName(String name);
}
