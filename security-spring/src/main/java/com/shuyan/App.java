package com.shuyan;

import com.shuyan.demo1.bean.Hello;
import org.springframework.context.ApplicationContext;
import org.springframework.context.support.ClassPathXmlApplicationContext;

/**
 * Hello world!
 *
 */
public class App 
{
    public static void main( String[] args )
    {
        // 从类路径下查找名为 “applicationContext.xml” 的spring配置文件，并获取 ApplicationContext 对象
        ApplicationContext ctx = new ClassPathXmlApplicationContext("applicationContext.xml");
        Hello hello = (Hello) ctx.getBean("hello");
        System.out.println(hello.toString());
    }
}
