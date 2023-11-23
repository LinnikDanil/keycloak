package com.example.keycloak;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/demo")
public class DemoController {

    @GetMapping("ooif")
    @PreAuthorize("hasRole('client_ooif')")
    public String hello() {
        return "Привет от ответственного ОИФ";
    }

    @GetMapping("/operd")
    @PreAuthorize("hasRole('client_operd')")
    public String hello2() {
        return "Привет от Опер дежурного";
    }
}
