package com.abc.spring.security.controller;

import com.abc.spring.security.entity.Role;
import com.abc.spring.security.entity.User;
import com.abc.spring.security.repository.RoleRepository;
import com.abc.spring.security.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

@RestController
@RequestMapping("/super-admin")
@RequiredArgsConstructor
public class SuperAdminController {
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;

    // ✅ 1. Add Role
    @PostMapping("/roles")
    public ResponseEntity<Role> addRole(@RequestBody Role role) {
        return ResponseEntity.ok(roleRepository.save(role));
    }

    // ✅ 4. Add User
    @PostMapping("/users")
    public ResponseEntity<User> addUser(@RequestBody User user) {
        return ResponseEntity.ok(userRepository.save(user));
    }

    // ✅ 5. Assign Roles to a User
    @PostMapping("/users/{userId}/roles")
    public ResponseEntity<?> assignRolesToUser(@PathVariable Long userId, @RequestBody Set<Long> roleIds) {
        Optional<User> userOpt = userRepository.findById(userId);
        if (userOpt.isEmpty()) return ResponseEntity.notFound().build();

        User user = userOpt.get();
        Set<Role> roles = new HashSet<>(roleRepository.findAllById(roleIds));
        user.getRoles().addAll(roles);

        return ResponseEntity.ok(userRepository.save(user));
    }
}
