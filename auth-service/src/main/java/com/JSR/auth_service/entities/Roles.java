package com.JSR.auth_service.entities;

import jakarta.persistence.*;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.*;

import java.util.HashSet;
import java.util.Set;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Builder
@Entity
@Table(
        name = "roles",
        uniqueConstraints = {
                @UniqueConstraint( columnNames = "name" )
        })
public class Roles {


    @Id
    @GeneratedValue( strategy = GenerationType.IDENTITY )
    private Long id;

    @NotBlank( message = "Role name is required" )
    @Size( max = 50, message = "Role name must be at most 50 characters" )
    @Column( nullable = false, unique = true, length = 50 )
    private String name;

    @Size( max = 255, message = "Description must be at most 255 characters" )
    @Column( length = 255 )
    private String description;


    @ManyToMany(mappedBy = "roles", fetch = FetchType.LAZY)
    private Set<Users>users =  new HashSet<>();




    @ManyToMany(fetch = FetchType.LAZY)
    @JoinTable(
            name = "role_permissions",
            joinColumns = @JoinColumn(name = "role_id"),
            inverseJoinColumns = @JoinColumn(name = "permission_id"),
            uniqueConstraints = @UniqueConstraint(
                    columnNames = {"role_id", "permission_id"}
            )

    )
    private Set<Permissions>permissions = new HashSet<>();

}
