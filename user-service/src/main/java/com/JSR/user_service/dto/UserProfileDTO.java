    package com.JSR.user_service.dto;


    import lombok.*;

    import java.util.List;

    @AllArgsConstructor
    @NoArgsConstructor
    @Getter
    @Setter
    @Builder
    public class UserProfileDTO {

        private Long id;
        private String keycloakUserId;
        private String email;
        private String fullName;
        private String phoneNumber;
        private String gender;
        private String dateOfBirth;
        private String profileImageUrl;
        private String preferences;
        private List <AddressDTO> addresses;
    }
