package com.JSR.auth_service.entities;

import jakarta.persistence.*;
import lombok.*;

import java.util.HashSet;
import java.util.Set;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Builder
@Entity
@Table(name = "permissions")
public class Permissions {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    private String name;

    private String description;


    @ManyToMany( mappedBy = "permissions", fetch =  FetchType.LAZY)
    private Set<Roles>roles = new HashSet<>();

}
