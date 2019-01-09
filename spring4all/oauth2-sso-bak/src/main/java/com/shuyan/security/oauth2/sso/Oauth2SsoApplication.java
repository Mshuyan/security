package com.shuyan.security.oauth2.sso;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import java.security.Principal;

/**
 * @author will
 */
@SpringBootApplication
public class Oauth2SsoApplication {
    public static void main(String[] args) {
        SpringApplication.run(Oauth2SsoApplication.class, args);
    }
}

