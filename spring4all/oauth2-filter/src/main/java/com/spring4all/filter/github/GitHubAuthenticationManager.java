package com.spring4all.filter.github;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import com.spring4all.domain.GitHubUser;
import org.jsoup.Connection;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class GitHubAuthenticationManager implements AuthenticationManager {
    /**
     * 默认角色列表
     */
    private static final List<GrantedAuthority> AUTHORITIES = new ArrayList<>();
    static {
        AUTHORITIES.add(new SimpleGrantedAuthority("ROLE_USER"));
    }
    /**
     * 获取 GitHub 用户信息的 API 地址
     */
    private final static String USER_INFO_URI = "https://api.github.com/user?access_token=";

    /**
     * 实现 authenticate 方法，用于身份认证
     * @param auth 提交上来的用户信息，这里传入的是 token
     * @return 数据库中查到的用户信息，这里为从github上获取的用户信息
     * @throws AuthenticationException 传入的用户信息参数错误
     */
    @Override
    public Authentication authenticate(Authentication auth) throws AuthenticationException {
        // 查看源码可知，这里获取的是前面传入的token
        if (auth.getName() != null) {
            GitHubUser user = getUserInfo(auth.getName());
            return new UsernamePasswordAuthenticationToken(user,
                    null, AUTHORITIES);
        }
        throw new BadCredentialsException("Bad Credentials");
    }

    /**
     * 使用token从github获取用户信息
     * @param accessToken token
     * @return 用户信息实体类
     */
    private GitHubUser getUserInfo(String accessToken) {
        try {
            Connection conn = Jsoup.connect(USER_INFO_URI + accessToken).ignoreContentType(true);
            Document doc = conn.get();
            String resultText = doc.text();
            JSONObject json = JSON.parseObject(resultText);

            GitHubUser user = new GitHubUser();
            user.setUsername(json.getString("login"));
            user.setUserId(json.getLong("id"));
            user.setAvatarUrl(json.getString("avatar_url"));
            user.setHtmlUrl(json.getString("html_url"));
            user.setNickName(json.getString("name"));
            user.setBio(json.getString("bio"));

            return user;
        }catch (IOException e){
            return null;
        }
    }
}
