package com.JSR.api_gateway.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.route.Route;
import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Flux;

@RestController

class DebugController {
    @Autowired
    private RouteLocator routeLocator;

    @GetMapping("/debug/routes")
    public Flux<Route> getRoutes() {
        return routeLocator.getRoutes();
    }
}