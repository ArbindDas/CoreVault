    package com.JSR.auth_service.repository;

    import com.JSR.auth_service.entities.OAuthAccount;
    import org.springframework.data.jpa.repository.JpaRepository;
    import org.springframework.stereotype.Repository;


    @Repository
    public interface OAuthAccountRepository extends JpaRepository<OAuthAccount , Long> {


    }
