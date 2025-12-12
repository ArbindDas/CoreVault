
package com.JSR.user_service.service;

import com.JSR.user_service.dto.AddressDTO;
import com.JSR.user_service.dto.UserProfileDTO;
import com.JSR.user_service.entities.Address;
import com.JSR.user_service.entities.UserProfile;
import com.JSR.user_service.repository.UserProfileRepository;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class UserProfileService {

    private static final Logger logger = LoggerFactory.getLogger(UserProfileService.class);
    private final UserProfileRepository profileRepository;

    public String getLoggedInUserEmail() {
        logger.info("Attempting to get logged-in user email");
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        if (auth != null && auth.isAuthenticated()) {
            String email = auth.getName();
            logger.info("Successfully retrieved user email: {}", email);
            return email; // This is the email from JWT
        }

        logger.error("User not authenticated - no valid authentication found");
        throw new RuntimeException("User not authenticated");
    }

    @Transactional(readOnly = true)
    public UserProfileDTO getProfile() {
        logger.info("Getting user profile");

        try {
            String email = getLoggedInUserEmail();
            logger.debug("Looking up profile for email: {}", email);

            UserProfile profile = profileRepository.findByEmail(email)
                    .orElseGet(() -> {
                        logger.info("No existing profile found for email: {}, creating new profile", email);

                        // Create new profile with just email
                        UserProfile newProfile = UserProfile.builder()
                                .email(email)
                                .fullName("") // Can be empty initially
                                .build();

                        UserProfile savedProfile = profileRepository.save(newProfile);
                        logger.info("New profile created successfully for email: {}, profile ID: {}",
                                email, savedProfile.getId());
                        return savedProfile;
                    });

            UserProfileDTO dto = convertToDTO(profile);
            logger.info("Profile DTO created successfully for email: {}", email);
            return dto;
        } catch (Exception e) {
            logger.error("Error occurred while getting profile: {}", e.getMessage(), e);
            throw e;
        }
    }

    @Transactional
    public UserProfileDTO updateProfile(UserProfileDTO updatedProfileDTO) {
        logger.info("Updating user profile from DTO");

        try {
            String email = getLoggedInUserEmail();
            logger.debug("Updating profile for email: {}", email);

            UserProfile existing = profileRepository.findByEmail(email)
                    .orElseThrow(() -> {
                        logger.error("Profile not found for email: {}", email);
                        return new RuntimeException("Profile not found");
                    });

            logger.debug("Existing profile found: ID={}, Email={}", existing.getId(), existing.getEmail());

            // Track what fields are being updated
            boolean anyFieldUpdated = false;

            // Update only provided fields from DTO
            if (updatedProfileDTO.getFullName() != null) {
                logger.debug("Updating fullName from '{}' to '{}'",
                        existing.getFullName(), updatedProfileDTO.getFullName());
                existing.setFullName(updatedProfileDTO.getFullName());
                anyFieldUpdated = true;
            }

            if (updatedProfileDTO.getPhoneNumber() != null) {
                logger.debug("Updating phoneNumber from '{}' to '{}'",
                        existing.getPhoneNumber(), updatedProfileDTO.getPhoneNumber());
                existing.setPhoneNumber(updatedProfileDTO.getPhoneNumber());
                anyFieldUpdated = true;
            }

            if (updatedProfileDTO.getGender() != null) {
                logger.debug("Updating gender from '{}' to '{}'",
                        existing.getGender(), updatedProfileDTO.getGender());
                existing.setGender(updatedProfileDTO.getGender());
                anyFieldUpdated = true;
            }

            if (updatedProfileDTO.getDateOfBirth() != null) {
                logger.debug("Updating dateOfBirth from '{}' to '{}'",
                        existing.getDateOfBirth(), updatedProfileDTO.getDateOfBirth());
                existing.setDateOfBirth(updatedProfileDTO.getDateOfBirth());
                anyFieldUpdated = true;
            }

            if (updatedProfileDTO.getProfileImageUrl() != null) {
                logger.debug("Updating profileImageUrl from '{}' to '{}'",
                        existing.getProfileImageUrl(), updatedProfileDTO.getProfileImageUrl());
                existing.setProfileImageUrl(updatedProfileDTO.getProfileImageUrl());
                anyFieldUpdated = true;
            }

            if (updatedProfileDTO.getPreferences() != null) {
                logger.debug("Updating preferences");
                existing.setPreferences(updatedProfileDTO.getPreferences());
                anyFieldUpdated = true;
            }

            // Note: Addresses should be updated separately through address-specific APIs
            // We don't update addresses here to maintain separation of concerns

            if (!anyFieldUpdated) {
                logger.warn("No fields were updated for profile ID: {}", existing.getId());
            } else {
                logger.info("Fields updated successfully for profile ID: {}", existing.getId());
            }

            UserProfile savedProfile = profileRepository.save(existing);
            logger.info("Profile updated successfully: ID={}, Email={}",
                    savedProfile.getId(), savedProfile.getEmail());

            return convertToDTO(savedProfile);
        } catch (Exception e) {
            logger.error("Error occurred while updating profile: {}", e.getMessage(), e);
            throw e;
        }
    }

    /**
     * Convert UserProfile entity to UserProfileDTO
     */
    private UserProfileDTO convertToDTO(UserProfile profile) {
        List<AddressDTO> addressDTOs = new ArrayList<>();

        if (profile.getAddresses() != null && !profile.getAddresses().isEmpty()) {
            addressDTOs = profile.getAddresses().stream()
                    .map(this::convertAddressToDTO)
                    .collect(Collectors.toList());
        }

        return UserProfileDTO.builder()
                .id(profile.getId())
                .email(profile.getEmail())
                .fullName(profile.getFullName())
                .phoneNumber(profile.getPhoneNumber())
                .gender(profile.getGender())
                .dateOfBirth(profile.getDateOfBirth())
                .profileImageUrl(profile.getProfileImageUrl())
                .preferences(profile.getPreferences())
                .addresses(addressDTOs)
                .build();
    }

    /**
     * Convert Address entity to AddressDTO
     */
    private AddressDTO convertAddressToDTO(Address address) {
        return AddressDTO.builder()
                .id(address.getId())
                .addressLine1(address.getAddressLine1())
                .addressLine2(address.getAddressLine2())
                .city(address.getCity())
                .state(address.getState())
                .country(address.getCountry())
                .zipCode(address.getZipCode())
                .isPrimary(address.isPrimary())
                .build();
    }

    /**
     * Convert UserProfileDTO to UserProfile entity (for update operations)
     * Note: This doesn't handle addresses - they should be managed separately
     */
    private UserProfile convertToEntity(UserProfileDTO dto) {
        return UserProfile.builder()
                .id(dto.getId())
                .email(dto.getEmail())
                .fullName(dto.getFullName())
                .phoneNumber(dto.getPhoneNumber())
                .gender(dto.getGender())
                .dateOfBirth(dto.getDateOfBirth())
                .profileImageUrl(dto.getProfileImageUrl())
                .preferences(dto.getPreferences())
                // Addresses are not set here - they should be managed separately
                .build();
    }
}