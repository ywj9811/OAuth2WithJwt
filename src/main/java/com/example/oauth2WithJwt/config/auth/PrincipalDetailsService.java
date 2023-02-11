package com.example.oauth2WithJwt.config.auth;

import com.example.oauth2WithJwt.domain.User;
import com.example.oauth2WithJwt.repository.UserRepo;
import com.example.oauth2WithJwt.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@RequiredArgsConstructor
@Service
public class PrincipalDetailsService implements UserDetailsService {
    private final UserService userService;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userService.findByUsername(username);
        if (user == null)
            throw new UsernameNotFoundException("해당 아이디가 존재하지 않습니다.");

        return new PrincipalDetails(user);
    }
}
