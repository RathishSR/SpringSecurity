package com.campercodes.springSecurity.repository;

import com.campercodes.springSecurity.entity.Token;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface TokenRepository extends JpaRepository<Token, String> {

    Optional<Token> findByJwToken(String token);

    List<Token> findByUserUsername(String username);
}
