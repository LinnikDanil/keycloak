package com.example.keycloak;

import jakarta.annotation.security.PermitAll;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/demo")
@Slf4j
public class DemoController {

    @GetMapping("ooif")
    @PreAuthorize("hasRole('client_ooif')")
    public String hello() {
        log.info("DEMO CONTROLLER: O OIF");

        return "Привет от ответственного ОИФ";
    }

    @GetMapping("/operd")
    @PreAuthorize("hasRole('client_operd')")
    public String hello2() {
        log.info("DEMO CONTROLLER: OPER D");

        return "Привет от Опер дежурного";
    }

    @GetMapping("/unauthorized")
    public String hello3() {
        log.info("DEMO CONTROLLER: unauthorized");

        return "Привет тебе";
    }

    @GetMapping("/admin")
    @PreAuthorize("hasRole('admin')")
    public String hello4() {
        log.info("DEMO CONTROLLER: ADMIN");

        return "ADMIN ADMIN ADMIN";
    }
}
