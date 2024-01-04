package com.example.demo.repositories;

import com.example.demo.model.User;
import org.springframework.stereotype.Repository;

@Repository
public class UserRepository {
    public User findByUserEmail(String email) {
        User user = new User(email, "1234");
        user.setFirstName("firstname");
        user.setLastName("lastname");
        return user;
    }
}
