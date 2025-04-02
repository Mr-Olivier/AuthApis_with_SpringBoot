package com.auth.authservice.security;

import com.auth.authservice.entity.User;
import com.auth.authservice.exception.AppException;
import com.auth.authservice.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;

@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new AppException("User not found with email: " + email, HttpStatus.NOT_FOUND));

        return new org.springframework.security.core.userdetails.User(
                user.getEmail(),
                user.getPassword(),
                user.isVerified(), // account is enabled only if email is verified
                true, // account non-expired
                true, // credentials non-expired
                true, // account non-locked
                new ArrayList<>()
        );
    }
}