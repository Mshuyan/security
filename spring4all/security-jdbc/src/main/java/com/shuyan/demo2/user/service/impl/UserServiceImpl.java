package com.shuyan.demo2.user.service.impl;

import com.shuyan.demo2.user.dto.UserDto;
import com.shuyan.demo2.user.mapper.UserMapper;
import com.shuyan.demo2.user.service.UserService;
import com.shuyan.demo2.user.util.RoleConstant;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class UserServiceImpl implements UserService {
    @Autowired
    private UserMapper userMapper;
    @Autowired
    private PasswordEncoder passwordEncoder;

    @Override
    public UserDto getByUsername(String userName) {
        return userMapper.getByUsername(userName);
    }

    @Override
    public Boolean addUser(UserDto user) {
        if(userMapper.getByUsername(user.getUsername()) != null){
            return false;
        }
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        // RoleConstant.ROLE_USER = "ROLE_USER"
        user.setRoles(RoleConstant.ROLE_USER);
        userMapper.addUser(user);
        return true;
    }
}
