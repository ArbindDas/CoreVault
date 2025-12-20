package com.JSR.user_service.controller;

import com.JSR.user_service.dto.AddressDTO;
import com.JSR.user_service.dto.UserProfileDTO;
import com.JSR.user_service.service.UserProfileService;
import jakarta.validation.Valid;
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




    @GetMapping("/test")
    public String test() {
        return "User service OK";
    }



    @PostMapping("/create-with-address")
    public ResponseEntity<UserProfileDTO> createProfileWithAddress(
            @Valid @RequestBody UserProfileDTO profileDTO) {
        log.info("=== Controller: Received create-with-address request ===");
        log.info("Request Body: {}", profileDTO);

        try {
            UserProfileDTO createdProfile = userProfileService.createProfileWithAddress(profileDTO);
            log.info("✅ Controller: Profile created successfully");
            return ResponseEntity.status(HttpStatus.CREATED).body(createdProfile);

        } catch (IllegalArgumentException e) {
            log.error("❌ Controller: Validation error - {}", e.getMessage());
            log.debug("Validation error details:", e);
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(null);

        } catch (RuntimeException e) {
            log.error("❌ Controller: Business logic error - {}", e.getMessage());
            log.debug("Business error details:", e);

            // Check what type of RuntimeException
            if (e.getMessage().contains("already exists")) {
                log.error("❌ Controller: CONFLICT - Profile already exists");
                return ResponseEntity.status(HttpStatus.CONFLICT)
                        .body(null);
            }

            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(null);

        } catch (Exception e) {
            log.error("❌ Controller: Internal server error - {}", e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(null);
        }
    }

    @GetMapping("/my-profile")
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


}