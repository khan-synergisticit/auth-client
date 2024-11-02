package com.americanworx.authclient.controller.user;

import com.americanworx.authclient.config.Constants;
import com.americanworx.authclient.domain.user.User;
import com.americanworx.authclient.service.app.AppService;
import com.americanworx.authclient.service.user.UserService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.*;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.List;


@RestController
@RequestMapping("/api/user")
@CrossOrigin(origins = Constants.SHOP_URL + ":8080")
public class UserController {

    @Autowired private UserService userService;
    @Autowired private AppService appService;

    @RequestMapping(value = "/find", method = RequestMethod.GET, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> getUserData(HttpServletRequest request, HttpServletResponse response) {
        var authentication = SecurityContextHolder.getContext().getAuthentication();
        System.out.println("Security details: " + authentication.getDetails().toString());
        String name = authentication.getName();
        System.out.println("name: " + name);
        User user = userService.getUserByEmail(name);

        if(user != null) {
            System.out.println("User: " + user.toString());
            return new ResponseEntity<>(user, HttpStatus.OK);
        }else {
            return new ResponseEntity<>(name, HttpStatus.NOT_FOUND);
        }
    }
}
