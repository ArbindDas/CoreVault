package com.JSR.user_service.entities;
import com.fasterxml.jackson.annotation.JsonManagedReference;
import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

@Entity
@Table(name = "user_profiles")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class UserProfile {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    // critical : Link to the Keycloak user
    @Column(unique = true, nullable = false)
    private  String keycloakUserId; // this is from jwt "sub" claim

    @Column(name = "email", nullable = false, unique = true)  // also from jwt "email" claim
    private String email;

    @Column(name = "full_name", nullable = false)
    private String fullName;

    @Column(name = "phone_number")
    private String phoneNumber;

    @Column(name = "gender")
    private String gender;

    @Column(name = "date_of_birth")
    private String dateOfBirth;

    @Column(name = "profile_image_url")
    private String profileImageUrl;

    @Column(name = "preferences")
    private String preferences;

    @JsonProperty(access = JsonProperty.Access.READ_ONLY)
    @Column(name = "created_at",nullable = false ,updatable = false)
    private LocalDateTime createdAt;

    @PrePersist
    public void prePersist(){
        if (this.createdAt == null){
            this.createdAt  = LocalDateTime.now();
        }
    }

    // FIX: Initialize the addresses list
    @Builder.Default
    @OneToMany(mappedBy = "userProfile", cascade = CascadeType.ALL, orphanRemoval = true)
    @JsonManagedReference
    private List<Address> addresses = new ArrayList<>();


}
