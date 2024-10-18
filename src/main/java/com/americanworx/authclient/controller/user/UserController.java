package com.americanworx.authclient.controller.user;

import com.americanworx.authclient.config.Constants;
import com.americanworx.authclient.domain.user.User;
import com.americanworx.authclient.service.user.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.*;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;


@RestController
@RequestMapping("/api/user")
@CrossOrigin(origins = Constants.SHOP_URL + ":8080")
public class UserController {

    @Autowired private UserService userService;


    @RequestMapping(value = "/find", method = RequestMethod.GET)
    public ResponseEntity<?> getUserData() {
        String name = SecurityContextHolder.getContext().getAuthentication().getName();
        System.out.println("name: " + name);
        User user = userService.getUserByEmail(name);
        if(user != null) {
            return ResponseEntity.ok(user);
        }else {
            return new ResponseEntity<>(name, HttpStatus.NOT_FOUND);
        }
    }
}
