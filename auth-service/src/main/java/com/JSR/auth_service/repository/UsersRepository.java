package com.JSR.auth_service.repository;

import com.JSR.auth_service.entities.Users;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UsersRepository extends JpaRepository<Users , Long> {
}
