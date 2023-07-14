package fr.fantasy.fantasyStatsback;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HelloWorldController {

    @Value("${test.test}")
    String test;
    @RequestMapping("/")
    public String hello()
    {
        return "Hello "+test;
    }
}