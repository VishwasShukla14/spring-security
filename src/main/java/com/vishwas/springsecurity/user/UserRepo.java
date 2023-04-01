package com.vishwas.springsecurity.user;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepo extends JpaRepository<User,Integer> {

    // Finding User by Email
    // SELECT u FROM USER u WHERE email=email
    Optional<User> findByEmail(String email);

}
