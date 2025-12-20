
package com.JSR.user_service.service;

import com.JSR.user_service.dto.AddressDTO;
import com.JSR.user_service.dto.UserProfileDTO;
import jakarta.transaction.Transactional;

public interface UserProfileService {

    // get profile from token
     UserProfileDTO getProfileFromToken();



//     UserProfileDTO createProfileFromToken();


    // NEW METHOD: Create profile with address details
    @Transactional
    UserProfileDTO createProfileWithAddress(UserProfileDTO profileDTO);
}