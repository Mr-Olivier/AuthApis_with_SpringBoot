package com.auth.authservice.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.time.LocalDateTime;

@Service
public class OtpService {

    private static final String OTP_CHARS = "0123456789";
    private static final int OTP_LENGTH = 6;

    @Value("${otp.expiration.minutes}")
    private int otpExpirationMinutes;

    private final SecureRandom random = new SecureRandom();

    public String generateOtp() {
        StringBuilder otp = new StringBuilder(OTP_LENGTH);
        for (int i = 0; i < OTP_LENGTH; i++) {
            otp.append(OTP_CHARS.charAt(random.nextInt(OTP_CHARS.length())));
        }
        return otp.toString();
    }

    public boolean isOtpExpired(LocalDateTime otpGeneratedTime) {
        if (otpGeneratedTime == null) {
            return true;
        }

        LocalDateTime expirationTime = otpGeneratedTime.plusMinutes(otpExpirationMinutes);
        return LocalDateTime.now().isAfter(expirationTime);
    }
}
