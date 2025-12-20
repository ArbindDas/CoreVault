package com.JSR.user_service.service.serviceImpl;

import com.JSR.user_service.dto.AddressDTO;
import com.JSR.user_service.dto.UserProfileDTO;
import com.JSR.user_service.entities.Address;
import com.JSR.user_service.entities.UserProfile;
import com.JSR.user_service.repository.AddressRepository;
import com.JSR.user_service.repository.UserProfileRepository;
import com.JSR.user_service.service.UserProfileService;
import com.JSR.user_service.utils.JwtUtil;
import lombok.extern.slf4j.Slf4j;
import org.jspecify.annotations.NonNull;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Service
@Transactional
@Slf4j

public class UserProfileServiceImpl implements UserProfileService {



    private final UserProfileRepository userProfileRepository;
    private final AddressRepository addressRepository;
    private final JwtUtil jwtUtil;

    public UserProfileServiceImpl(UserProfileRepository userProfileRepository, AddressRepository addressRepository, JwtUtil jwtUtil) {
        this.userProfileRepository = userProfileRepository;
        this.addressRepository = addressRepository;
        this.jwtUtil = jwtUtil;
    }

    @Override
    public UserProfileDTO getProfileFromToken() {

        log.info("=== getProfileFromToken() called ===");

        // Log full JWT details for debugging
        jwtUtil.logFullJwtDetails();
        // get user info from token
        String userId = jwtUtil.getUserId();
        String email = jwtUtil.getEmail();
        String username = jwtUtil.getUsername();

        log.debug("Extracted values - UserId: {}, Email: {}, Username: {}",
                userId, email, username);

        if (userId == null) {
            log.error("❌ User not authenticated - userId is null");
            log.debug("Stack trace for debugging:", new RuntimeException("Debug stack trace"));
            throw new RuntimeException("User not authenticated");
        }
        // find existing user
        return userProfileRepository.findByKeycloakUserId(userId)
                .map(this::convertToDTO)
                .orElse(null);
    }


    @Transactional
    protected void updateAddresses(UserProfile userProfile, List<AddressDTO> addressDTOs) {
        // Remove existing addresses
        addressRepository.deleteByUserProfile(userProfile);

        // Add new addresses
        List<Address> addresses = addressDTOs.stream()
                .map(dto -> convertToAddressEntity(dto, userProfile))
                .collect(Collectors.toList());

        addressRepository.saveAll(addresses);
        userProfile.setAddresses(addresses);
    }




    @Override
    @Transactional
    public UserProfileDTO createProfileWithAddress(@NonNull UserProfileDTO profileDTO) {
        log.info("=== START createProfileWithAddress ===");
        log.info("Received DTO: {}", profileDTO);

        // Get user ID from JWT token instead of request body
        String keycloakUserId = jwtUtil.getUserId();
        String email = jwtUtil.getEmail();
        String fullName = jwtUtil.getFullName();

        log.info("Creating profile for user: {}, email: {}, name: {}",
                keycloakUserId, email, fullName);

        // Validate extracted data

        // Validate extracted data
        if (keycloakUserId == null || keycloakUserId.isEmpty()) {
            log.error("❌ Keycloak User ID is null or empty");
            throw new IllegalArgumentException("Keycloak User ID not found in token");
        }

        if (email == null || email.isEmpty()) {
            log.error("❌ Email is null or empty");
            throw new IllegalArgumentException("Email not found in token");
        }

        if (fullName == null || fullName.isEmpty()) {
            log.error("❌ Full name is null or empty");
            throw new IllegalArgumentException("Full name not found in token");
        }

        // Check if profile already exists - WITH DETAILED LOGGING
        log.info("Checking if profile exists for Keycloak User ID: '{}'", keycloakUserId);
        Optional<UserProfile> existingByUserId = userProfileRepository.findByKeycloakUserId(keycloakUserId);
        log.info("Profile exists by User ID: {}", existingByUserId.isPresent());

        log.info("Checking if profile exists for Email: '{}'", email);
        Optional<UserProfile> existingByEmail = userProfileRepository.findByEmail(email);
        log.info("Profile exists by Email: {}", existingByEmail.isPresent());


        if (existingByUserId.isPresent()) {
            UserProfile existing = existingByUserId.get();
            log.error("❌ Profile already exists! ID: {}, Email: {}, Name: {}",
                    existing.getId(), existing.getEmail(), existing.getFullName());
            throw new RuntimeException("User profile already exists for this Keycloak user ID");
        }


        if (existingByEmail.isPresent()) {
            UserProfile existing = existingByEmail.get();
            log.error("❌ Profile with this email already exists! ID: {}, Email: {}, Name: {}",
                    existing.getId(), existing.getEmail(), existing.getFullName());
            throw new RuntimeException("User profile already exists for this email");
        }
        log.info("✅ No existing profile found. Proceeding with creation...");

        // Use token data for critical fields, allow updates from DTO for other fields
        UserProfile userProfile = UserProfile.builder()
                .keycloakUserId(keycloakUserId)  // From token
                .email(email)                    // From token
                .fullName(fullName)              // From token
                .phoneNumber(profileDTO.getPhoneNumber())
                .gender(profileDTO.getGender())
                .dateOfBirth(profileDTO.getDateOfBirth())
                .profileImageUrl(profileDTO.getProfileImageUrl())
                .preferences(profileDTO.getPreferences())
                .createdAt(LocalDateTime.now())
                .addresses(new ArrayList<>()) // ← IMPORTANT: Initialize empty list
                .build();

        // Save user profile first
        UserProfile savedProfile = userProfileRepository.save(userProfile);
        log.info("User profile created with ID: {}", savedProfile.getId());

        // Process addresses if provided
        if (profileDTO.getAddresses() != null && !profileDTO.getAddresses().isEmpty()) {
            log.info("Processing {} addresses for user profile", profileDTO.getAddresses().size());

            boolean hasPrimary = false;

            for (AddressDTO addressDTO : profileDTO.getAddresses()) {
                // Validate address
                validateAddress(addressDTO);

                // Create address entity
                Address address = Address.builder()
                        .type(addressDTO.getType())
                        .addressLine1(addressDTO.getAddressLine1())
                        .addressLine2(addressDTO.getAddressLine2())
                        .city(addressDTO.getCity())
                        .state(addressDTO.getState())
                        .country(addressDTO.getCountry())
                        .zipCode(addressDTO.getZipCode())
                        .userProfile(savedProfile)
                        .build();

                // Handle primary address logic
                Boolean isPrimary = addressDTO.getIsPrimary();
                if (isPrimary == null) {
                    // If not specified and no primary exists yet, set as primary
                    address.setIsPrimary(!hasPrimary);
                    if (!hasPrimary) {
                        hasPrimary = true;
                    }
                } else if (isPrimary) {
                    if (hasPrimary) {
                        throw new IllegalArgumentException("Only one address can be marked as primary");
                    }
                    address.setIsPrimary(true);
                    hasPrimary = true;
                } else {
                    address.setIsPrimary(false);
                }

                // Save address
                addressRepository.save(address);
                savedProfile.getAddresses().add(address);
                log.info("Address added: {}, City: {}", address.getAddressLine1(), address.getCity());
            }

            // If no address was marked as primary and addresses exist, mark first one as primary
            if (!hasPrimary && !savedProfile.getAddresses().isEmpty()) {
                savedProfile.getAddresses().get(0).setIsPrimary(true);
                addressRepository.save(savedProfile.getAddresses().get(0));
                log.info("Marked first address as primary");
            }
        }

        // Return the created profile with addresses
        return convertToDTO(savedProfile);
    }


    // Helper method for address validation
    private void validateAddress(AddressDTO addressDTO) {
        if (addressDTO.getAddressLine1() == null || addressDTO.getAddressLine1().isEmpty()) {
            throw new IllegalArgumentException("Address line 1 is required");
        }

        if (addressDTO.getCity() == null || addressDTO.getCity().isEmpty()) {
            throw new IllegalArgumentException("City is required");
        }

        if (addressDTO.getCountry() == null || addressDTO.getCountry().isEmpty()) {
            throw new IllegalArgumentException("Country is required");
        }

        // Optional: Add country-specific validation
        if ("India".equalsIgnoreCase(addressDTO.getCountry())) {
            validateIndianAddress(addressDTO);
        }
    }
    // Optional: Indian address validation
    private void validateIndianAddress(AddressDTO addressDTO)   {
        if (addressDTO.getState() == null || addressDTO.getState().isEmpty()) {
            throw new IllegalArgumentException("State is required for Indian addresses");
        }

        if (addressDTO.getZipCode() == null || addressDTO.getZipCode().isEmpty()) {
            throw new IllegalArgumentException("PIN code is required for Indian addresses");
        }

        // Validate PIN code format (6 digits)
        if (!addressDTO.getZipCode().matches("^[1-9][0-9]{5}$")) {
            throw new IllegalArgumentException("Invalid Indian PIN code format. Must be 6 digits");
        }
    }

    public UserProfileDTO convertToDTO(UserProfile userProfile){

        List<AddressDTO> addressDTOS = userProfile.getAddresses()
                .stream().map(this::convertToAddressDTO)
                .toList();
        return UserProfileDTO.builder()
                .id(userProfile.getId())
                .keycloakUserId(userProfile.getKeycloakUserId())
                .email(userProfile.getEmail())
                .fullName(userProfile.getFullName())
                .phoneNumber(userProfile.getPhoneNumber())
                .gender(userProfile.getGender())
                .dateOfBirth(userProfile.getDateOfBirth())
                .profileImageUrl(userProfile.getProfileImageUrl())
                .preferences(userProfile.getPreferences())
                .addresses(addressDTOS)
                .build();
    }

    private AddressDTO convertToAddressDTO(Address address) {
        return  AddressDTO.builder()
                .id(address.getId())
                .type(address.getType())
                .addressLine1(address.getAddressLine1())
                .addressLine2(address.getAddressLine2())
                .city(address.getCity())
                .state(address.getState())
                .country(address.getCountry())
                .zipCode(address.getZipCode())
                .isPrimary(address.getIsPrimary())
                .build();

    }




    private Address convertToAddressEntity(AddressDTO dto, UserProfile userProfile) {
        return Address.builder()
                .type(dto.getType())
                .addressLine1(dto.getAddressLine1())
                .addressLine2(dto.getAddressLine2())
                .city(dto.getCity())
                .state(dto.getState())
                .country(dto.getCountry())
                .zipCode(dto.getZipCode())
                .isPrimary(dto.getIsPrimary() != null ? dto.getIsPrimary() : false)
                .userProfile(userProfile)
                .build();
    }
}
