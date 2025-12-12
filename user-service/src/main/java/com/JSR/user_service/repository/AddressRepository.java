package com.JSR.user_service.repository;


import com.JSR.user_service.entities.Address;
import com.JSR.user_service.entities.UserProfile;
import io.lettuce.core.dynamic.annotation.Param;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface AddressRepository extends JpaRepository<Address, Long> {
    // Find addresses by user's email through UserProfile
    @Query("SELECT a FROM Address a WHERE a.userProfile.email = :email")
    List<Address> findByUserEmail(@Param("email") String email);


    List<Address> findByUserProfile(UserProfile userProfile);
    List<Address> findByUserProfileAndIsPrimary(UserProfile userProfile, boolean isPrimary);
    int countByUserProfile(UserProfile userProfile);

    // Custom query to fetch addresses with profile in one query
    @Query("SELECT a FROM Address a JOIN FETCH a.userProfile WHERE a.userProfile = :profile")
    List<Address> findByUserProfileWithProfile(@Param("profile") UserProfile profile);
}


