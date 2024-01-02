package ba.com.ak.authserver.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import ba.com.ak.authserver.entity.Role;

@Repository
public interface RoleRepository extends JpaRepository<Role, Long> {

    Role findByRoleCode(String roleCode);
}