package com.shuyan.demo2.user.controller;

import com.shuyan.demo2.user.dto.UserDto;
import com.shuyan.demo2.user.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

/**
 * @author will
 */
@Controller
public class TestController {

    @Autowired
    private UserService userServiceImpl;

    @GetMapping("/test")
    @ResponseBody
    public String home(){
        return "not need authenticated";
    }

    @GetMapping("/user")
    @ResponseBody
    public String user(){
        return "must authenticated";
    }

    @GetMapping("/login")
    public String login(){
        return "/login";
    }

    @GetMapping("/")
    public String index(){
        return "index";
    }

    @GetMapping("/register")
    public String register(){
        return "register";
    }

    @PostMapping("/register")
    @ResponseBody
    public String registerPost(UserDto userDto){
        Boolean aBoolean = userServiceImpl.addUser(userDto);
        return aBoolean? "success":"failed";
    }
}
