package com.americanworx.authclient.service.user;

import com.americanworx.authclient.domain.user.User;

public interface UserService {
    User createUser(User user);
    User updateUser(User user);
    User getUserByEmail(String email);
}
