package com.gwkim.security.oauth2;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TestController {

    @GetMapping("/api/v1/vehicle-owner")
    public String vehicleOwner() {
        return "test";
    }
}
