package com.shuyan.demo1.bean;

import lombok.Data;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Data
@Component
public class Hello {
    @Value("${sys.hello.name}")
    private String name;
}
