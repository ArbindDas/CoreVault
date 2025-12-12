package com.JSR.user_service.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserProfileDTO {
    private Long id;
    private String email;
    private String fullName;
    private String phoneNumber;
    private String gender;
    private String dateOfBirth;
    private String profileImageUrl;
    private String preferences;
    private List<AddressDTO> addresses;
}