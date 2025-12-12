
package com.JSR.user_service.service;

import com.JSR.user_service.dto.AddressDTO;
import com.JSR.user_service.entities.Address;
import com.JSR.user_service.entities.UserProfile;
import com.JSR.user_service.repository.AddressRepository;
import com.JSR.user_service.repository.UserProfileRepository;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class AddressService {

    private static final Logger logger = LoggerFactory.getLogger(AddressService.class);
    private final AddressRepository addressRepository;
    private final UserProfileRepository profileRepository;
    private final UserProfileService userProfileService;

    /**
     * Get all addresses for the logged-in user
     */
    @Transactional(readOnly = true)
    public List<AddressDTO> getUserAddresses() {
        logger.info("Getting all addresses for user");

        String email = userProfileService.getLoggedInUserEmail();
        UserProfile profile = profileRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("Profile not found"));

        List<Address> addresses = addressRepository.findByUserProfile(profile);
        logger.info("Found {} addresses for user: {}", addresses.size(), email);

        return addresses.stream()
                .map(this::convertToDTO)
                .collect(Collectors.toList());
    }

    /**
     * Add a new address for the logged-in user
     */
    @Transactional
    public AddressDTO addAddress(AddressDTO addressDTO) {
        logger.info("Adding new address for user");

        String email = userProfileService.getLoggedInUserEmail();
        UserProfile profile = profileRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("Profile not found"));

        // Check if this is the first address
        boolean isFirstAddress = addressRepository.countByUserProfile(profile) == 0;

        Address address = Address.builder()
                .userProfile(profile)
                .addressLine1(addressDTO.getAddressLine1())
                .addressLine2(addressDTO.getAddressLine2())
                .city(addressDTO.getCity())
                .state(addressDTO.getState())
                .country(addressDTO.getCountry())
                .zipCode(addressDTO.getZipCode())
                .isPrimary(isFirstAddress || addressDTO.getIsPrimary())
                .build();

        // If this address is set as primary, unset others
        if (address.isPrimary()) {
            unsetOtherPrimaryAddresses(profile);
        }

        Address savedAddress = addressRepository.save(address);
        logger.info("Address added successfully with ID: {}", savedAddress.getId());

        return convertToDTO(savedAddress);
    }

    /**
     * Update an existing address
     */
    @Transactional
    public AddressDTO updateAddress(Long addressId, AddressDTO addressDTO) {
        logger.info("Updating address with ID: {}", addressId);

        String email = userProfileService.getLoggedInUserEmail();
        Address address = addressRepository.findById(addressId)
                .orElseThrow(() -> new RuntimeException("Address not found"));

        // Verify address belongs to the logged-in user
        if (!address.getUserProfile().getEmail().equals(email)) {
            throw new RuntimeException("Address does not belong to user");
        }

        // Update fields
        if (addressDTO.getAddressLine1() != null) {
            address.setAddressLine1(addressDTO.getAddressLine1());
        }
        if (addressDTO.getAddressLine2() != null) {
            address.setAddressLine2(addressDTO.getAddressLine2());
        }
        if (addressDTO.getCity() != null) {
            address.setCity(addressDTO.getCity());
        }
        if (addressDTO.getState() != null) {
            address.setState(addressDTO.getState());
        }
        if (addressDTO.getCountry() != null) {
            address.setCountry(addressDTO.getCountry());
        }
        if (addressDTO.getZipCode() != null) {
            address.setZipCode(addressDTO.getZipCode());
        }

        // Handle primary flag
        if (addressDTO.getIsPrimary() && !address.isPrimary()) {
            unsetOtherPrimaryAddresses(address.getUserProfile());
            address.setPrimary(true);
        }

        Address updatedAddress = addressRepository.save(address);
        logger.info("Address updated successfully: ID={}", updatedAddress.getId());

        return convertToDTO(updatedAddress);
    }

    /**
     * Delete an address
     */
    @Transactional
    public void deleteAddress(Long addressId) {
        logger.info("Deleting address with ID: {}", addressId);

        String email = userProfileService.getLoggedInUserEmail();
        Address address = addressRepository.findById(addressId)
                .orElseThrow(() -> new RuntimeException("Address not found"));

        // Verify address belongs to the logged-in user
        if (!address.getUserProfile().getEmail().equals(email)) {
            throw new RuntimeException("Address does not belong to user");
        }

        addressRepository.delete(address);
        logger.info("Address deleted successfully: ID={}", addressId);

        // If deleted address was primary, set another address as primary if available
        if (address.isPrimary()) {
            List<Address> remainingAddresses = addressRepository.findByUserProfile(address.getUserProfile());
            if (!remainingAddresses.isEmpty()) {
                remainingAddresses.get(0).setPrimary(true);
                addressRepository.save(remainingAddresses.get(0));
                logger.info("Set address ID: {} as new primary", remainingAddresses.get(0).getId());
            }
        }
    }

    /**
     * Set an address as primary
     */
    @Transactional
    public void setPrimaryAddress(Long addressId) {
        logger.info("Setting address as primary: ID={}", addressId);

        String email = userProfileService.getLoggedInUserEmail();
        Address address = addressRepository.findById(addressId)
                .orElseThrow(() -> new RuntimeException("Address not found"));

        // Verify address belongs to the logged-in user
        if (!address.getUserProfile().getEmail().equals(email)) {
            throw new RuntimeException("Address does not belong to user");
        }

        unsetOtherPrimaryAddresses(address.getUserProfile());
        address.setPrimary(true);
        addressRepository.save(address);

        logger.info("Address set as primary successfully: ID={}", addressId);
    }

    /**
     * Unset primary flag from all other addresses of the user
     */
    private void unsetOtherPrimaryAddresses(UserProfile profile) {
        List<Address> primaryAddresses = addressRepository.findByUserProfileAndIsPrimary(profile, true);
        primaryAddresses.forEach(addr -> {
            if (addr.isPrimary()) {
                addr.setPrimary(false);
                addressRepository.save(addr);
                logger.debug("Unset primary flag from address ID: {}", addr.getId());
            }
        });
    }

    /**
     * Convert Address entity to AddressDTO
     */
    private AddressDTO convertToDTO(Address address) {
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

//  **
//          * Get all addresses for the logged-in user
//     */
    @Transactional(readOnly = true)
    public List<AddressDTO> getAllAddresses() {
        logger.info("Getting all addresses for logged-in user");

        try {
            String email = userProfileService.getLoggedInUserEmail();
            logger.debug("Fetching addresses for user email: {}", email);

            UserProfile profile = profileRepository.findByEmail(email)
                    .orElseThrow(() -> {
                        logger.error("User profile not found for email: {}", email);
                        return new RuntimeException("User profile not found");
                    });

            // Fetch addresses with user profile to avoid N+1 problem
            List<Address> addresses = addressRepository.findByUserProfileWithProfile(profile);

            if (addresses.isEmpty()) {
                logger.info("No addresses found for user: {}", email);
                return Collections.emptyList();
            }

            logger.info("Found {} addresses for user: {}", addresses.size(), email);

            return addresses.stream()
                    .map(this::convertToDTO)
                    .collect(Collectors.toList());

        } catch (Exception e) {
            logger.error("Error occurred while fetching addresses: {}", e.getMessage(), e);
            throw e;
        }
    }
}