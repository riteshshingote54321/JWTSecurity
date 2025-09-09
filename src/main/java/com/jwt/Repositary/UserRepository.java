package com.jwt.Repositary;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.jwt.Entity.User;

public interface UserRepository extends JpaRepository<User, Long>{
	 Optional<User> findByUsername(String username);
	    boolean existsByUsername(String username);
}
