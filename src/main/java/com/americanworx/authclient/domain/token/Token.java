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
    private String tokenValue;
    private String tokenType;
    private Instant expiresAt;
}
