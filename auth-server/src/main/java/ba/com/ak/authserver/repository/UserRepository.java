package ba.com.ak.authserver.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import ba.com.ak.authserver.entity.User;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {

    User findUserByUsername(String username);
}