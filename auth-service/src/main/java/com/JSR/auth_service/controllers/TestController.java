package com.JSR.auth_service.controllers;

import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
@RequestMapping("/api/test")
public class TestController {


    @GetMapping()
    public String test(){
        log.info("the test endpoint is working,......");
        return "test endpoint is working......";
    }
}
