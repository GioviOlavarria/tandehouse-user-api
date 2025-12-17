package tande.house.usersapi.repo;

import org.springframework.data.jpa.repository.JpaRepository;
import tande.house.usersapi.model.User;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByEmail(String email);
    boolean existsByEmail(String email);
}
