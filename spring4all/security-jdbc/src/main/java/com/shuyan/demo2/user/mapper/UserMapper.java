package com.shuyan.demo2.user.mapper;

import com.shuyan.demo2.user.dto.UserDto;
import org.springframework.stereotype.Repository;

/**
 * @author will
 */
@Repository
public interface UserMapper {
    UserDto getByUsername(String username);
    void addUser(UserDto user);
}
