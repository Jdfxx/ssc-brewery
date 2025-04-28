package guru.sfg.brewery.repositories.security;

import guru.sfg.brewery.domain.security.LoginFail;
import guru.sfg.brewery.domain.security.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.sql.Timestamp;
import java.util.List;

public interface LoginFailureRepository extends JpaRepository<LoginFail, Integer> {

    List<LoginFail> findAllByUserAndCreatedDateIsAfter(User user, Timestamp timestamp);
}
