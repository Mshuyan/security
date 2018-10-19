package com.spring4all.domain;

import lombok.Data;

/**
 * @author will
 */
@Data
public class GitHubUser {
    private String username;
    private Long userId;
    private String avatarUrl;
    private String htmlUrl;
    private String nickName;
    private String bio;
}
