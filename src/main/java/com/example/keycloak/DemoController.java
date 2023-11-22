package com.example.keycloak;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/demo")
public class DemoController {

    @GetMapping
    @PreAuthorize("hasRole('client_ooif')")
    public String hello() {
        return "Hellp from SB and Keycloak";
    }

    @GetMapping("/hello2")
    @PreAuthorize("hasRole('client_operd')")
    public String hello2() {
        return "Hellp from SB and Keycloak ADMIN";
    }
}
