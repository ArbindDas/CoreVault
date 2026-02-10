package com.JSr.newarrivals.entity;

import jakarta.persistence.*;
import jakarta.validation.constraints.*;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.LocalDateTime;

@Entity
@Table(name = "product_images",
        uniqueConstraints = @UniqueConstraint(
                name = "uk_product_position",
                columnNames = {"product_id", "position"}
        ))
@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
public class ProductImages {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @NotBlank(message = "S3 key is required")
    @Size(max = 1024, message = "S3 key cannot exceed 1024 characters")
    @Pattern(regexp = "^[a-zA-Z0-9\\-_.*/]+$",
            message = "S3 key contains invalid characters")
    @Column(name = "s3_key", nullable = false, length = 1024)
    private String s3Key;

    @Size(max = 2048, message = "URL cannot exceed 2048 characters")
    @Pattern(regexp = "^(https?://|/).*$|^$",
            message = "URL must start with http://, https:// or /")
    @Column(length = 2048)
    private String url;

    @NotNull(message = "Position is required")
    @Min(value = 0, message = "Position must be at least 0")
    @Max(value = 99, message = "Position cannot exceed 99")
    @Column(nullable = false)
    private Integer position;

    @NotNull(message = "Product is required")
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "product_id", nullable = false)
    private Product product;

    @Size(max = 100, message = "Alt text cannot exceed 100 characters")
    @Column(name = "alt_text", length = 100)
    private String altText;

    @Column(name = "is_primary")
    private Boolean isPrimary = false;

    @Column(name = "created_at", updatable = false)
    private LocalDateTime createdAt;

    @Column(name = "updated_at")
    private LocalDateTime updatedAt;

    @PrePersist
    protected void onCreate() {
        createdAt = LocalDateTime.now();
        updatedAt = LocalDateTime.now();
    }

    @PreUpdate
    protected void onUpdate() {
        updatedAt = LocalDateTime.now();
    }

    /**
     * Auto-generate URL if not provided
     */
    @PostLoad
    @PostPersist
    @PostUpdate
    public void ensureUrl() {
        if ((url == null || url.isBlank()) && s3Key != null && !s3Key.isBlank()) {
            String bucketUrl = System.getenv("CDN_URL") != null
                    ? System.getenv("CDN_URL")
                    : "https://cdn.example.com";
            this.url = bucketUrl + "/" + s3Key;
        }
    }

    /**
     * Validate S3 key format
     */
    @AssertTrue(message = "S3 key must be valid")
    public boolean isS3KeyValid() {
        if (s3Key == null) return false;
        return !s3Key.contains("//") && !s3Key.startsWith("/") && !s3Key.endsWith("/");
    }
}