package com.example.oauth2WithJwt.service;

import com.example.oauth2WithJwt.domain.User;
import com.example.oauth2WithJwt.repository.UserRepo;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
@RequiredArgsConstructor
public class UserService {
    private final UserRepo userRepo;

    public User findByUsername(String username) {
        Optional<User> user = userRepo.findByUsername(username);
        if (user.isEmpty())
            return null;
        return user.get();
    }

    public User save(User user) {
        user.userRoleSet();
        User save = userRepo.save(user);
        return save;
    }

}
