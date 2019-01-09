package com.shuyan.security.oauth2.sso.controller;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

/**
 * @author will
 */
@RestController
public class OAuth2LoginController {

    @GetMapping("/")
    public Map<String, Object> index(
            @RegisteredOAuth2AuthorizedClient OAuth2AuthorizedClient authorizedClient,
            @AuthenticationPrincipal OAuth2User oauth2User) {
        Map<String,Object> map = new HashMap<>(1024);
        map.put("userName", oauth2User.getName());
        map.put("clientName", authorizedClient.getClientRegistration().getClientName());
        map.put("userAttributes", oauth2User.getAttributes());
        return map;
    }
}
