
package com.JSR.user_service.service;

import com.JSR.user_service.dto.AddressDTO;
import com.JSR.user_service.dto.UserProfileDTO;
import jakarta.transaction.Transactional;

public interface UserProfileService {

    // get profile from token
     UserProfileDTO getProfileFromToken();


     UserProfileDTO createNewProfile(String keycloakUserId , String email , String fullName);

     UserProfileDTO createProfileFromToken();

//     UserProfileDTO updateProfile(String authHeader , UserProfileDTO profileDTO);
UserProfileDTO updateProfile(UserProfileDTO profileDTO);

    @Transactional
    UserProfileDTO addAddress(AddressDTO addressDTO);

    @Transactional
    UserProfileDTO updateAddress(Long addressId, AddressDTO addressDTO);

    @Transactional
    void deleteAddress(Long addressId);
}