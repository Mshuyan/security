package com.shuyan.demo2.user.service;

import com.shuyan.demo2.user.dto.UserDto;

public interface UserService {
    UserDto getByUsername(String userName);
    Boolean addUser(UserDto user);
}
