package com.auth.authservice.service;

import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Slf4j
public class EmailService {

    private final JavaMailSender mailSender;

    @Async
    public void sendOtpEmail(String to, String otp, String subject) {
        try {
            MimeMessage mimeMessage = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(mimeMessage, "utf-8");

            String htmlContent = buildOtpEmailTemplate(otp);

            helper.setText(htmlContent, true);
            helper.setTo(to);
            helper.setSubject(subject);
            helper.setFrom("noreply@authservice.com");

            mailSender.send(mimeMessage);
            log.info("Sent OTP email to: {}", to);
        } catch (MessagingException e) {
            log.error("Failed to send OTP email to: {}", to, e);
            throw new RuntimeException("Failed to send OTP email", e);
        }
    }

    private String buildOtpEmailTemplate(String otp) {
        return "<div style='font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 5px;'>"
                + "<h2 style='color: #333366;'>Your One-Time Password</h2>"
                + "<p>Please use the following OTP to complete your verification:</p>"
                + "<h1 style='font-size: 42px; letter-spacing: 2px; color: #333366; background-color: #f0f0f0; padding: 10px; text-align: center; border-radius: 5px;'>"
                + otp
                + "</h1>"
                + "<p>This OTP is valid for 5 minutes.</p>"
                + "<p>If you didn't request this OTP, please ignore this email.</p>"
                + "<p>Thank you,<br>Auth Service Team</p>"
                + "</div>";
    }
}
