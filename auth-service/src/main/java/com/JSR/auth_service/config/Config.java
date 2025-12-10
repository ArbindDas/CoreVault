//package com.JSR.auth_service.config;
//
//import com.JSR.auth_service.entities.Roles;
//import com.JSR.auth_service.repository.RolesRepository;
//import org.springframework.boot.CommandLineRunner;
//import org.springframework.stereotype.Component;
//
//@Component  // ← Add this
//public class Config implements CommandLineRunner {
//
//    private final RolesRepository rolesRepository;
//
//    public Config(RolesRepository rolesRepository) {
//        this.rolesRepository = rolesRepository;
//    }
//
//    @Override
//    public void run(String... args) throws Exception {
//        if (rolesRepository.findByName("ROLE_USER").isEmpty()) {
//            rolesRepository.save(Roles.builder()
//                    .name("ROLE_USER")
//                    .description("Default user role")
//                    .build());
//        }
//        if (rolesRepository.findByName("ROLE_ADMIN").isEmpty()) {
//            rolesRepository.save(Roles.builder()
//                    .name("ROLE_ADMIN")
//                    .description("Administrator role")
//                    .build());
//        }
//    }
//}
