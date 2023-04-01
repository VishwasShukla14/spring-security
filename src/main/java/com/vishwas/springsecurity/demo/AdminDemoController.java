package com.vishwas.springsecurity.demo;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@RestController
@RequestMapping("/api/demo/admin")
public class AdminDemoController {

    // Demo Hello string shown after the user is authenticated
    @GetMapping("/hello")
    public ResponseEntity<String> sayHello(Principal principal){
        return ResponseEntity.ok("Hello admin "+principal.getName());
    }

}
