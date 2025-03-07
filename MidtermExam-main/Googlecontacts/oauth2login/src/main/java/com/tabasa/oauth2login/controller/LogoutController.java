package com.tabasa.oauth2login.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;

@RestController
public class LogoutController {

    private static final Logger logger = LoggerFactory.getLogger(LogoutController.class);
    private final OAuth2AuthorizedClientService authorizedClientService;

    public LogoutController(OAuth2AuthorizedClientService authorizedClientService) {
        this.authorizedClientService = authorizedClientService;
    }

    @GetMapping("/logout")
    public ResponseEntity<String> logout(HttpServletRequest request, HttpServletResponse response) {
        try {
            // Invalidate session
            HttpSession session = request.getSession(false);
            if (session != null) {
                session.invalidate();
            }

            // Clear security context
            SecurityContextHolder.clearContext();

            // Revoke token (if using OAuth2)
            OAuth2AuthorizedClient client = authorizedClientService.loadAuthorizedClient("google", "user");
            if (client != null) {
                OAuth2AccessToken accessToken = client.getAccessToken();
                if (accessToken != null) {
                    logger.info("Revoking access token: {}", accessToken.getTokenValue());
                    // You can add logic here to revoke the access token if needed
                }
            }

            // Redirect to login page or return success response
            response.sendRedirect("/login");
            return ResponseEntity.ok("Logged out successfully");

        } catch (IOException e) {
            logger.error("Error during logout", e);
            return ResponseEntity.internalServerError().body("Logout failed: " + e.getMessage());
        }
    }
}
