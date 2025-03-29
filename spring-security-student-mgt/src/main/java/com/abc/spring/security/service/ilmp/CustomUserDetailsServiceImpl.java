package com.abc.spring.security.service.ilmp;

import com.abc.spring.security.dto.CustomUserDetails;
import com.abc.spring.security.entity.User;
import com.abc.spring.security.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class CustomUserDetailsServiceImpl implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));
        /**
         * This is the user-details or actual user objet for the spring
         * authorities is important for roles/permission based access
         * userId is required current user can show only his result
         */
        return new CustomUserDetails(user);
    }
}
