package com.shuyan.demo2.config;

import com.shuyan.demo2.user.dto.UserDto;
import com.shuyan.demo2.user.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

/**
 * @author will
 * 实现 UserDetailsService 接口，重写 loadUserByUsername 方法
 */
@Service
public class CustomUserDetailServiceImpl implements UserDetailsService {

    /**
     * 注入自己实现的 UserService
     */
    @Autowired
    private UserService userServiceImpl;

    /**
     * 根据用户名查询该用户的密码、权限等信息
     * @param username 需要验证的用户名
     * @return 数据库中查到的用户信息
     * @throws UsernameNotFoundException 未找到用户异常
     */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        UserDto userDto = userServiceImpl.getByUsername(username);
        if(userDto == null){
            throw new UsernameNotFoundException("用户不存在！");
        }
        // 权限转换
        List<SimpleGrantedAuthority> simpleGrantedAuthorities = createAuthorities(userDto.getRoles());
        // 将查询结果封装到指定的对象中并返回
        return new User(userDto.getUsername(), userDto.getPassword(), simpleGrantedAuthorities);
    }

    /**
     * 将权限字符串转换为List<SimpleGrantedAuthority>
     * @param roleStr 数据库中查到的权限字符串
     * @return 需要的权限集合
     */
    private List<SimpleGrantedAuthority> createAuthorities(String roleStr){
        String[] roles = roleStr.split(",");
        List<SimpleGrantedAuthority> simpleGrantedAuthorities = new ArrayList<>();
        for (String role : roles) {
            simpleGrantedAuthorities.add(new SimpleGrantedAuthority(role));
        }
        return simpleGrantedAuthorities;
    }
}
