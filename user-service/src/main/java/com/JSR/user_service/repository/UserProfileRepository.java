package com.JSR.user_service.repository;


import com.JSR.user_service.dto.AddressDTO;
import com.JSR.user_service.dto.UserProfileDTO;
import com.JSR.user_service.entities.UserProfile;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserProfileRepository extends JpaRepository<UserProfile, Long> {

    // most important find by keycloak user ID
   Optional<UserProfile>findByKeycloakUserId(String keycloakUserId);
   Optional<UserProfile>findByEmail(String email);
   boolean existsByKeycloakUserId(String keycloakUserId);
   Boolean existsByEmail(String email);


}

