package com.JSR.user_service.controller;

import com.JSR.user_service.dto.UserProfileDTO;
import com.JSR.user_service.entities.UserProfile;
import com.JSR.user_service.service.UserProfileService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/user")
@RequiredArgsConstructor
public class UserProfileController {

    private final UserProfileService profileService;

    @GetMapping("/profile")
    public ResponseEntity<UserProfileDTO> getProfile() {
        return ResponseEntity.ok(profileService.getProfile());
    }

    @PutMapping("/profile")
    public ResponseEntity<UserProfileDTO> updateProfile(@RequestBody UserProfileDTO updatedProfile) {
        return ResponseEntity.ok(profileService.updateProfile(updatedProfile));
    }
}