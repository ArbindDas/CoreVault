package com.JSR.user_service.controller;


import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/test")
@Slf4j
public class TestController {


    @GetMapping()
    public Map<String , String>test(){
        Map<String , String>response = new HashMap<>();
        response.put("Message", "Test Endpoint is Working fine ......");
        log.info("The test endpoint is working fine .....");
        return response;
    }
}


