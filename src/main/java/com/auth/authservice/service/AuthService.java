package com.auth.authservice.service;

import com.auth.authservice.dto.request.*;
import com.auth.authservice.dto.response.ApiResponse;
import com.auth.authservice.dto.response.AuthResponse;
import com.auth.authservice.dto.response.UserDto;
import com.auth.authservice.entity.User;
import com.auth.authservice.exception.AppException;
import com.auth.authservice.repository.UserRepository;
import com.auth.authservice.security.JwtUtils;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Optional;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtils jwtUtils;
    private final AuthenticationManager authenticationManager;
    private final UserDetailsService userDetailsService;
    private final OtpService otpService;
    private final EmailService emailService;

    @Transactional
    public ApiResponse register(RegisterRequest request) {
        // Validate password match
        if (!request.getPassword().equals(request.getConfirmPassword())) {
            throw new AppException("Passwords do not match", HttpStatus.BAD_REQUEST);
        }

        // Check if email already exists
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new AppException("Email already registered", HttpStatus.CONFLICT);
        }

        // Create new user
        User user = new User();
        user.setFirstName(request.getFirstName());
        user.setLastName(request.getLastName());
        user.setEmail(request.getEmail());
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        user.setVerified(false);

        // Generate OTP for email verification
        String otp = otpService.generateOtp();
        user.setOtp(otp);
        user.setOtpGeneratedTime(LocalDateTime.now());

        // Save user
        userRepository.save(user);

        // Send OTP email
        emailService.sendOtpEmail(
                user.getEmail(),
                otp,
                "Email Verification OTP"
        );

        return ApiResponse.success("Registration successful. Please verify your email with the OTP sent.");
    }

    @Transactional
    public ApiResponse verifyOtp(VerifyOtpRequest request) {
        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new AppException("User not found", HttpStatus.NOT_FOUND));

        // Check if OTP is valid
        if (!user.getOtp().equals(request.getOtp())) {
            throw new AppException("Invalid OTP", HttpStatus.BAD_REQUEST);
        }

        // Check if OTP is expired
        if (otpService.isOtpExpired(user.getOtpGeneratedTime())) {
            throw new AppException("OTP has expired", HttpStatus.BAD_REQUEST);
        }

        // Update user verification status
        user.setVerified(true);
        user.setOtpVerifiedTime(LocalDateTime.now());
        userRepository.save(user);

        return ApiResponse.success("Email verification successful. You can now login.");
    }

    public AuthResponse login(LoginRequest request) {
        try {
            // Authenticate user
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            request.getEmail(),
                            request.getPassword()
                    )
            );

            // Get user details
            UserDetails userDetails = userDetailsService.loadUserByUsername(request.getEmail());
            User user = userRepository.findByEmail(request.getEmail())
                    .orElseThrow(() -> new AppException("User not found", HttpStatus.NOT_FOUND));

            // Check if email is verified
            if (!user.isVerified()) {
                throw new AppException("Email not verified", HttpStatus.FORBIDDEN);
            }

            // Generate JWT token
            String token = jwtUtils.generateToken(userDetails);

            // Build response
            return AuthResponse.builder()
                    .token(token)
                    .email(user.getEmail())
                    .firstName(user.getFirstName())
                    .lastName(user.getLastName())
                    .build();

        } catch (DisabledException e) {
            throw new AppException("Account is disabled", HttpStatus.FORBIDDEN);
        } catch (BadCredentialsException e) {
            throw new AppException("Invalid email or password", HttpStatus.UNAUTHORIZED);
        }
    }

    @Transactional
    public ApiResponse forgotPassword(ForgotPasswordRequest request) {
        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new AppException("User not found", HttpStatus.NOT_FOUND));

        // Generate OTP
        String otp = otpService.generateOtp();
        user.setOtp(otp);
        user.setOtpGeneratedTime(LocalDateTime.now());
        userRepository.save(user);

        // Send OTP email
        emailService.sendOtpEmail(
                user.getEmail(),
                otp,
                "Password Reset OTP"
        );

        return ApiResponse.success("OTP has been sent to your email for password reset");
    }

    @Transactional
    public ApiResponse resetPassword(ResetPasswordRequest request) {
        // Validate password match
        if (!request.getNewPassword().equals(request.getConfirmPassword())) {
            throw new AppException("Passwords do not match", HttpStatus.BAD_REQUEST);
        }

        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new AppException("User not found", HttpStatus.NOT_FOUND));

        // Check if OTP is valid
        if (!user.getOtp().equals(request.getOtp())) {
            throw new AppException("Invalid OTP", HttpStatus.BAD_REQUEST);
        }

        // Check if OTP is expired
        if (otpService.isOtpExpired(user.getOtpGeneratedTime())) {
            throw new AppException("OTP has expired", HttpStatus.BAD_REQUEST);
        }

        // Update password
        user.setPassword(passwordEncoder.encode(request.getNewPassword()));
        user.setOtp(null); // Clear OTP
        userRepository.save(user);

        return ApiResponse.success("Password has been reset successfully");
    }

    public ApiResponse logout() {
        // In a JWT-based authentication system, server-side logout is not typically needed
        // as the token is stored on the client side
        // We can implement a token blacklist if needed

        return ApiResponse.success("Logged out successfully");
    }

    public UserDto getCurrentUser(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new AppException("User not found", HttpStatus.NOT_FOUND));

        return UserDto.builder()
                .id(user.getId())
                .firstName(user.getFirstName())
                .lastName(user.getLastName())
                .email(user.getEmail())
                .isVerified(user.isVerified())
                .build();
    }

    @Transactional
    public ApiResponse resendOtp(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new AppException("User not found", HttpStatus.NOT_FOUND));

        if (user.isVerified()) {
            throw new AppException("Email is already verified", HttpStatus.BAD_REQUEST);
        }

        // Generate new OTP
        String otp = otpService.generateOtp();
        user.setOtp(otp);
        user.setOtpGeneratedTime(LocalDateTime.now());
        userRepository.save(user);

        // Send OTP email
        emailService.sendOtpEmail(
                user.getEmail(),
                otp,
                "Email Verification OTP"
        );

        return ApiResponse.success("OTP has been resent to your email");
    }
}
