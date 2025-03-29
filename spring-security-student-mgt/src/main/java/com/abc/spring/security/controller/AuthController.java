package com.abc.spring.security.controller;

import com.abc.spring.security.dto.LoginRequest;
import com.abc.spring.security.utils.JwtUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthenticationManager authenticationManager;
    private final UserDetailsService userDetailsService;
    private final JwtUtil jwtUtil;

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest request) {

        /**
         * Authenticate user
         * verify the user's credentials (username & password).
         */
        /**
         *  * Possible Reasons for Failure:
         *  * Incorrect username/password → Throws BadCredentialsException
         *  *
         *  * User is disabled → Throws DisabledException
         *  *
         *  * Account locked → Throws LockedException
         *  *
         *  * Password is not in BCrypt format → Throws IllegalArgumentException: Encoded password does not look like BCrypt
         *  *
         **/
        try {
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword())
            );
        } catch (Exception e) {
            throw new RuntimeException(e.getMessage());
        }

        // Load user details
        UserDetails userDetails = userDetailsService.loadUserByUsername(request.getUsername());

        // Generate JWT token
        String token = jwtUtil.generateToken(userDetails);

        // Send response with JWT token
        Map<String, Object> response = new HashMap<>();
        response.put("username", userDetails.getUsername());
        response.put("token", token);

        return ResponseEntity.ok(response);
    }
}
