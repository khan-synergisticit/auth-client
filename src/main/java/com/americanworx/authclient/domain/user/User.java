package com.americanworx.authclient.domain.user;


import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import lombok.*;

import java.util.Date;

@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
@Entity
@ToString
public class User {
    @Id
    private Integer id;

    private String name;

    private String mobileNumber;

    private String email;

    private String address;

    private String city;

    private String state;

    private String pincode;

    private String profileImage;

    private String role;

    private Boolean isEnable = false;

    private Boolean accountNonLocked = false;

    private Integer failedAttempt;

    private Date lockTime;

    private String resetToken;

    private String accessToken;
    private String refreshToken;
}
