package com.JSR.user_service.service.serviceImpl;

import com.JSR.user_service.dto.AddressDTO;
import com.JSR.user_service.dto.UserProfileDTO;
import com.JSR.user_service.entities.Address;
import com.JSR.user_service.entities.UserProfile;
import com.JSR.user_service.repository.AddressRepository;
import com.JSR.user_service.repository.UserProfileRepository;
import com.JSR.user_service.service.UserProfileService;
import com.JSR.user_service.utils.JwtUtil;
import jakarta.transaction.Transactional;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.stream.Collectors;

@Service
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

        // get user info from token
        String userId = jwtUtil.getUserId();
        String email = jwtUtil.getEmail();
        String username = jwtUtil.getUsername();

        if (userId == null) {
            throw new RuntimeException("User not authenticated");
        }
        // find existing user
        return userProfileRepository.findByKeycloakUserId(userId)
                .map(this::convertToDTO)
                .orElse(null);
    }

    @Override
    public UserProfileDTO createNewProfile(String keycloakUserId, String email, String fullName) {

        // Check if profile already exists
        if (userProfileRepository.existsByKeycloakUserId(keycloakUserId)) {
            throw new RuntimeException("User profile already exists");
        }

        // Get username from JWT for default full name if not provided
        String username = jwtUtil.getUsername();

        // create a profile
        UserProfile profile = UserProfile.builder()
                .keycloakUserId(keycloakUserId)
                .email(email)
                .fullName(fullName !=null ? fullName : username)
                .build();

        UserProfile savedProfile = userProfileRepository.save(profile);

        return convertToDTO(savedProfile);

    }

    @Transactional
    @Override
    public UserProfileDTO createProfileFromToken() {

        // Get user info from JWT token using JwtUtil
        String userId = jwtUtil.getUserId();
        String email = jwtUtil.getEmail();
        String username = jwtUtil.getUsername();

        if (userId == null) {
            throw new RuntimeException("User not authenticated");
        }

        // Check if profile already exists
        if (userProfileRepository.existsByKeycloakUserId(userId)){
            throw new RuntimeException("User profile already exists");
        }

        return createNewProfile(userId , email , username);

    }

    @Override
    @Transactional
    public UserProfileDTO updateProfile(UserProfileDTO profileDTO) {
        // Get user ID from JWT token using JwtUtil
        String userId = jwtUtil.getUserId();

        if (userId == null) {
            throw new RuntimeException("User not authenticated");
        }

        // Find existing profile
        UserProfile existingProfile = userProfileRepository.findByKeycloakUserId(userId)
                .orElseThrow(() -> new RuntimeException("User profile not found"));

        // Update profile fields
        if (profileDTO.getFullName() != null) {
            existingProfile.setFullName(profileDTO.getFullName());
        }
        if (profileDTO.getPhoneNumber() != null) {
            existingProfile.setPhoneNumber(profileDTO.getPhoneNumber());
        }
        if (profileDTO.getGender() != null) {
            existingProfile.setGender(profileDTO.getGender());
        }
        if (profileDTO.getDateOfBirth() != null) {
            existingProfile.setDateOfBirth(profileDTO.getDateOfBirth());
        }
        if (profileDTO.getProfileImageUrl() != null) {
            existingProfile.setProfileImageUrl(profileDTO.getProfileImageUrl());
        }
        if (profileDTO.getPreferences() != null) {
            existingProfile.setPreferences(profileDTO.getPreferences());
        }

        // Handle addresses update
        if (profileDTO.getAddresses() != null && !profileDTO.getAddresses().isEmpty()) {
            updateAddresses(existingProfile, profileDTO.getAddresses());
        }

        UserProfile updatedProfile = userProfileRepository.save(existingProfile);

        return convertToDTO(updatedProfile);
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

    @Transactional
    @Override
    public UserProfileDTO addAddress(AddressDTO addressDTO) {
        String userId = jwtUtil.getUserId();

        if (userId == null) {
            throw new RuntimeException("User not authenticated");
        }

        UserProfile userProfile = userProfileRepository.findByKeycloakUserId(userId)
                .orElseThrow(() -> new RuntimeException("User profile not found"));

        // If this is the first address or marked as primary, set it as primary
        if (addressDTO.getIsPrimary() == null || addressDTO.getIsPrimary()) {
            // Set all existing addresses as non-primary
            userProfile.getAddresses().forEach(address -> address.setIsPrimary(false));
        }

        Address newAddress = convertToAddressEntity(addressDTO, userProfile);
        userProfile.getAddresses().add(newAddress);

        UserProfile updatedProfile = userProfileRepository.save(userProfile);

        return convertToDTO(updatedProfile);
    }

    @Transactional
    @Override
    public UserProfileDTO updateAddress(Long addressId, AddressDTO addressDTO) {
        String userId = jwtUtil.getUserId();

        if (userId == null) {
            throw new RuntimeException("User not authenticated");
        }

        UserProfile userProfile = userProfileRepository.findByKeycloakUserId(userId)
                .orElseThrow(() -> new RuntimeException("User profile not found"));

        Address existingAddress = addressRepository.findByIdAndUserProfile(addressId, userProfile)
                .orElseThrow(() -> new RuntimeException("Address not found"));

        // Update address fields
        if (addressDTO.getType() != null) {
            existingAddress.setType(addressDTO.getType());
        }
        if (addressDTO.getAddressLine1() != null) {
            existingAddress.setAddressLine1(addressDTO.getAddressLine1());
        }
        if (addressDTO.getAddressLine2() != null) {
            existingAddress.setAddressLine2(addressDTO.getAddressLine2());
        }
        if (addressDTO.getCity() != null) {
            existingAddress.setCity(addressDTO.getCity());
        }
        if (addressDTO.getState() != null) {
            existingAddress.setState(addressDTO.getState());
        }
        if (addressDTO.getCountry() != null) {
            existingAddress.setCountry(addressDTO.getCountry());
        }
        if (addressDTO.getZipCode() != null) {
            existingAddress.setZipCode(addressDTO.getZipCode());
        }
        if (addressDTO.getIsPrimary() != null) {
            // If setting as primary, update other addresses
            if (addressDTO.getIsPrimary()) {
                userProfile.getAddresses().forEach(address -> {
                    if (!address.getId().equals(addressId)) {
                        address.setIsPrimary(false);
                    }
                });
            }
            existingAddress.setIsPrimary(addressDTO.getIsPrimary());
        }

        addressRepository.save(existingAddress);

        return convertToDTO(userProfile);
    }


    @Transactional
    @Override
    public void deleteAddress(Long addressId) {
        String userId = jwtUtil.getUserId();

        if (userId == null) {
            throw new RuntimeException("User not authenticated");
        }

        UserProfile userProfile = userProfileRepository.findByKeycloakUserId(userId)
                .orElseThrow(() -> new RuntimeException("User profile not found"));

        Address address = addressRepository.findByIdAndUserProfile(addressId, userProfile)
                .orElseThrow(() -> new RuntimeException("Address not found"));

        addressRepository.delete(address);

        // If deleted address was primary, set another address as primary
        if (address.getIsPrimary() && !userProfile.getAddresses().isEmpty()) {
            userProfile.getAddresses().stream()
                    .filter(a -> !a.getId().equals(addressId))
                    .findFirst()
                    .ifPresent(newPrimary -> {
                        newPrimary.setIsPrimary(true);
                        addressRepository.save(newPrimary);
                    });
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
                .addressLine1(address.getAddressLine2())
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
