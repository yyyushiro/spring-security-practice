package com.example.securitypractice.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping
public class HelloController {

    @GetMapping("/hello-form")
    public String sayHelloForm() {
        return "Hello, form!";
    }

    @GetMapping("/hello-basic")
    public String sayHelloBasic() {
        return "Hello, basic!";
    }
}
