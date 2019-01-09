package com.spring4all.controller;

import com.spring4all.domain.GitHubUser;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class UserController {

    @GetMapping("/user")
    public String user(@AuthenticationPrincipal UsernamePasswordAuthenticationToken userAuthentication, Model model){
        GitHubUser user = (GitHubUser) userAuthentication.getPrincipal();
        model.addAttribute("username", user.getUsername());
        model.addAttribute("avatar", user.getAvatarUrl());
        return "user/user";
    }

}
