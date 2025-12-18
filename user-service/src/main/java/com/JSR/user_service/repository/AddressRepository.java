package com.JSR.user_service.repository;
import com.JSR.user_service.entities.Address;
import com.JSR.user_service.entities.UserProfile;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface AddressRepository extends JpaRepository<Address, Long> {


    void deleteByUserProfile(UserProfile userProfile);

    Optional<Address> findByIdAndUserProfile(Long addressId, UserProfile userProfile);
}


