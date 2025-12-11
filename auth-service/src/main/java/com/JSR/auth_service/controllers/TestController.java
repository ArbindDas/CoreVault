package com.JSR.auth_service.controllers;

import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@Slf4j
@RestController
@RequestMapping("/api/test")
public class TestController {

    @GetMapping("/message")
    public Map<String , String>getJaiShreeRamMessage(){
        Map<String  , String>response = new HashMap<>();
        response.put("Message", "Jai Shree Ram");
        return response;
    }
}
