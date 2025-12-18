package com.JSR.user_service.controller;

import com.JSR.user_service.dto.AddressDTO;
import com.JSR.user_service.dto.UserProfileDTO;
import com.JSR.user_service.service.UserProfileService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/users")
@Slf4j
public class UserProfileController {


    private final UserProfileService userProfileService;

    public UserProfileController(UserProfileService userProfileService) {
        this.userProfileService = userProfileService;
    }

    @GetMapping("/me")
    public ResponseEntity<UserProfileDTO> getMyProfile() {
        log.info("=== GET /api/users/me endpoint called ===");
        log.debug("Request headers and details can be logged here");

        try {
            UserProfileDTO profile = userProfileService.getProfileFromToken();

            if (profile != null) {
                log.info("✅ Successfully retrieved profile for user: {}", profile.getFullName());
                log.debug("Profile details: {}", profile);
                return ResponseEntity.ok(profile);
            } else {
                log.warn("⚠️ Profile not found for authenticated user");
                return ResponseEntity.notFound().build();
            }
        } catch (RuntimeException e) {
            log.error("❌ Error in getMyProfile: {}", e.getMessage());
            log.debug("Exception details:", e);

            // Differentiate between authentication error and other errors
            if (e.getMessage().contains("not authenticated")) {
                log.error("❌ Authentication failed - no valid JWT token provided");

            } else {
                log.error("❌ Internal server error: {}", e.getMessage());
                return ResponseEntity.notFound().build();
            }
            return ResponseEntity.notFound().build();
        }
    }

//    @GetMapping("/me")
//    public ResponseEntity<UserProfileDTO> getMyProfile() {
//        try {
//            UserProfileDTO profile = userProfileService.getProfileFromToken();
//            return profile != null ?
//                    ResponseEntity.ok(profile) :
//                    ResponseEntity.notFound().build();
//        } catch (RuntimeException e) {
//            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
//        }
//    }

    @PostMapping("/create")
    public ResponseEntity<UserProfileDTO> createProfile() {
        try {
            UserProfileDTO createdProfile = userProfileService.createProfileFromToken();
            return ResponseEntity.status(HttpStatus.CREATED).body(createdProfile);
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body(null);
        }
    }

    @PutMapping("/update")
    public ResponseEntity<UserProfileDTO> updateProfile(@RequestBody UserProfileDTO profileDTO) {
        try {
            UserProfileDTO updatedProfile = userProfileService.updateProfile(profileDTO);
            return ResponseEntity.ok(updatedProfile);
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body(null);
        }
    }

    @PostMapping("/addresses")
    public ResponseEntity<UserProfileDTO> addAddress(@RequestBody AddressDTO addressDTO) {
        try {
            UserProfileDTO updatedProfile = userProfileService.addAddress(addressDTO);
            return ResponseEntity.ok(updatedProfile);
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body(null);
        }
    }

    @PutMapping("/addresses/{addressId}")
    public ResponseEntity<UserProfileDTO> updateAddress(
            @PathVariable Long addressId,
            @RequestBody AddressDTO addressDTO) {
        try {
            UserProfileDTO updatedProfile = userProfileService.updateAddress(addressId, addressDTO);
            return ResponseEntity.ok(updatedProfile);
        } catch (RuntimeException e) {
            return ResponseEntity.notFound().build();
        }
    }

    @DeleteMapping("/addresses/{addressId}")
    public ResponseEntity<Void> deleteAddress(@PathVariable Long addressId) {
        try {
            userProfileService.deleteAddress(addressId);
            return ResponseEntity.noContent().build();
        } catch (RuntimeException e) {
            return ResponseEntity.notFound().build();
        }
    }
}