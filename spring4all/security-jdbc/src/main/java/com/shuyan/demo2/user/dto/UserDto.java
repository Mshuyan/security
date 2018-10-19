package com.shuyan.demo2.user.dto;

import lombok.Data;

/**
 * @author will
 */
@Data
public class UserDto {
    private Long id;
    private String username;
    private String password;
    private String nickName;
    private String roles;
}
