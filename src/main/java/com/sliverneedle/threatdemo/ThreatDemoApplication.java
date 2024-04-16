package com.sliverneedle.threatdemo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration;

@SpringBootApplication()
public class ThreatDemoApplication {

    public static void main(String[] args) {
        SpringApplication.run(ThreatDemoApplication.class, args);
    }

}
