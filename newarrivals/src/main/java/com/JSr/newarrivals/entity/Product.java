package com.JSr.newarrivals.entity;

import com.JSr.newarrivals.enums.Category;
import feign.Param;
import jakarta.persistence.*;
import jakarta.validation.Valid;
import jakarta.validation.constraints.*;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.LocalDateTime;
import java.util.List;

@Entity
@Table(name = "products")
@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
public class Product {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @NotBlank(message = "Product name is required")
    @Size(min = 2 , max = 100 , message = "Product name must be between 2 and 100 characters")
    @Pattern(regexp = "^(?!\\s*$)[A-Za-z0-9][A-Za-z0-9\\s\\-_,.&'()]{1,98}[A-Za-z0-9]$",
            message = "Product name must start and end with alphanumeric, can contain spaces, " +
                    "hyphens, underscores, commas, periods, ampersands, apostrophes, and parentheses"
    )
    @Column(nullable = false , length = 100)
    private String name;

    @NotBlank(message = "Product description is required")
    @Size(min = 10 , max = 2000 , message ="Description must be between 10 and 2000 characters")
    @Column(nullable = false , columnDefinition = "TEXT")
    private String description;

    @NotNull(message = "Price is required")
    @Positive(message = "Price must be greater than 0")
    @DecimalMin(value = "0.01" , message = "Price must be at least 0.01")
    @DecimalMax(value = "999999.99", message = "Price cannot exceed 999,999.99")
    @Digits(integer = 6, fraction = 2 , message = "Price must have max 6 integer digits and 2 decimal places")
    @Column(nullable = false, precision = 8,scale = 2)
    private Double price;

    @PositiveOrZero(message = "Original price cannot be negative")
    @DecimalMax(value = "999999.99" , message = "Original price cannot be exceed 999,999.99")
    @Digits(integer = 6 , fraction = 2,message = "Original price must have max 6 integer digits and 2 decimal places")
    @Column(precision = 8 , scale = 2)
    private Double originalPrice;

    @NotNull(message = "Category is required")
    @Column(nullable = false, length = 50)
    @Enumerated(EnumType.STRING)
    private Category category;

    @Min(value = 0 , message = "Rating cannot be less than 0")
    @Max(value = 5 , message = "Rating cannot be greater then 5")
    @Digits(integer = 1 , fraction = 1 , message = "Rating must be in format x.x(e.g., 4.5)")
    @Column(precision = 2 ,scale = 1)
    private Double rating;


    @PastOrPresent(message = "Creation date cannot be in the future ")
    @Column(name = "created_at", updatable = false)
    private LocalDateTime createdAt;

    @PastOrPresent(message = "Update date cannot be in the future ")
    @Column(name = "update_at")
    private  LocalDateTime updatedAt;

    @NotNull(message = "Trending status must be specified")
    @Column(name = "is_trending", nullable = false)
    private Boolean isTrending;


    @Valid
    @OneToMany(
            mappedBy = "product",
            cascade = CascadeType.ALL,
            orphanRemoval = true
    )
    private List<ProductImages>images;

    @PrePersist
    public void onCreate() {
        createdAt = LocalDateTime.now( );
        updatedAt = LocalDateTime.now();
        validatePriceConsistency();
    }

    @PreUpdate
    public void onUpdate(){
        updatedAt = LocalDateTime.now();
        validatePriceConsistency();
    }


    /**
     * Business rule validation: Ensure originalPrice >= price when both are set
     * This allows for discount/sale pricing
     */

    /**
     * This method checks that the original price of the product
     * is not less than the current price.
     *
     * Why:
     * - originalPrice should represent the "old" or "list" price.
     * - price represents the "current" selling price (may be discounted).
     * - If originalPrice < price, it doesn't make sense (you can't have a discount
     *   where the "original" price is smaller than the current price).
     */
    private void  validatePriceConsistency(){
        if(originalPrice!=null && price!=null){
            // If originalPrice is less than current price, it's invalid
            if (originalPrice<price){
                throw new IllegalStateException(
                        String.format("Original price (%.2f) cannot be less than current price(%.2f)", originalPrice, price)
                );
            }
        }
    }

    /**
     * Custom validation method for product name based on business rules.
     *
     * This method ensures that the product name does NOT contain any prohibited words
     * such as "free", "win", "winner", or "urgent".
     *
     * How it works:
     * - Annotated with @AssertTrue so that if the method returns false,
     *   validation will fail with the provided message.
     */
    @AssertTrue(message = "Product name must not contain prohibited words")
    private boolean isValidProductName() {

        // If the name is null, we assume it's valid here (other validations like @NotBlank
        // can handle null/empty names separately)
        if (name == null) return true;

        // List of words that are not allowed in the product name
        String[] prohibitedWords = {"free", "win", "winner", "urgent"};

        // Convert the product name to lowercase for case-insensitive comparison
        String lowerName = name.toLowerCase();

        // Check each prohibited word
        for (String word : prohibitedWords) {
            // If the product name contains a prohibited word, validation fails
            if (lowerName.contains(word)) {
                return false;
            }
        }

        // No prohibited words found → validation passes
        return true;
    }



    /**
     * Business logic: Check if product is on sale
     */

    public boolean isOnSale(){
        return originalPrice !=null &&
                price!=null &&
                originalPrice>price&&
                originalPrice>0;
    }

    /**
     * Calculate discount percentage if on sale
     */
    public Double getDiscountPercentage(){
        if (!isOnSale()){
            return null;
        }
        return ((originalPrice-price)/originalPrice) *100;
    }

}



