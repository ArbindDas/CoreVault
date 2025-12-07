package com.JSR.auth_service.entities;

import com.JSR.auth_service.enums.AuthProvider;
import jakarta.persistence.*;
import lombok.*;
import java.time.LocalDateTime;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Builder
@Entity
@Table(name = "oauth_accounts",
        uniqueConstraints = {
                @UniqueConstraint(columnNames = {"provider", "provider_user_id"})
        })
public class OAuthAccount {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    @Enumerated(EnumType.STRING)
    private AuthProvider provider;  // GOOGLE, GITHUB, FACEBOOK, etc.

    @Column(name = "provider_user_id", nullable = false)
    private String providerUserId;

    @Column(name = "created_at")
    private LocalDateTime createdAt = LocalDateTime.now();

    // One user can have many social accounts
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private Users user;
}
