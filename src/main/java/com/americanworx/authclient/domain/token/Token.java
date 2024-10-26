package com.americanworx.authclient.domain.token;

import jakarta.persistence.Entity;
import lombok.*;

import java.time.Instant;

@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
@ToString
public class Token {
    private String accessToken;
    private String refreshToken;
    private Instant expiresAt;
}
