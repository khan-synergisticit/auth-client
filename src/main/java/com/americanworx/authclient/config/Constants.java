package com.americanworx.authclient.config;

import org.springframework.beans.factory.annotation.Value;

public class Constants {
    @Value("${url.shop}")
    private static String shop;
    @Value("${url.auth-server}")
    private static String auth_server;

    public static final String CLIENT_CREDENTIALS = "shopping:donkey";
    public static final String AUTH_SERVER_URL= auth_server;
    public static final String SHOP_URL =shop;
}
