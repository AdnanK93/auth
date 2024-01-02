package ba.com.ak.authserver.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import ba.com.ak.authserver.entity.OAuth2ClientRole;

@Repository
public interface OAuth2ClientRoleRepository extends JpaRepository<OAuth2ClientRole, Long> {

    OAuth2ClientRole findByClientRegistrationIdAndRoleCode(String clientRegistrationId, String roleCode);
}