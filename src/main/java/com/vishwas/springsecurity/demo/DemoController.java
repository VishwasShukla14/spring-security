package com.vishwas.springsecurity.demo;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/demo")
public class DemoController {

    // Demo Hello string shown after the user is authenticated
    @GetMapping("/hello")
    public ResponseEntity<String> sayHello(){
        return ResponseEntity.ok("Hello from secret endpoint");
    }

}
