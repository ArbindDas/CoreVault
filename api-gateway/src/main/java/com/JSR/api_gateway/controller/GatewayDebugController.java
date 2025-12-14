package com.JSR.api_gateway.controller;

import org.springframework.cloud.gateway.route.RouteDefinition;
import org.springframework.cloud.gateway.route.RouteDefinitionLocator;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/gateway")
public class GatewayDebugController {

    private final RouteDefinitionLocator routeDefinitionLocator;

    public GatewayDebugController(RouteDefinitionLocator routeDefinitionLocator) {
        this.routeDefinitionLocator = routeDefinitionLocator;
    }

    @GetMapping("/routes")
    public Mono<Map<String, Object>> getRoutes() {
        return routeDefinitionLocator.getRouteDefinitions()
                .collectList()
                .map(routes -> {
                    Map<String, Object> result = new HashMap<>();
                    result.put("count", routes.size());
                    result.put("routes", routes.stream()
                            .map(route -> Map.of(
                                    "id", route.getId(),
                                    "uri", route.getUri().toString(),
                                    "predicates", route.getPredicates(),
                                    "filters", route.getFilters()
                            ))
                            .toList());
                    return result;
                });
    }
}