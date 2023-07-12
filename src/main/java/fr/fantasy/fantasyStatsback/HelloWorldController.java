package fr.fantasy.fantasyStatsback;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HelloWorldController {
    @RequestMapping("/")
    public String hello()
    {
        return "Hello Everyone";
    }

    echo "# fantasyStats-back" >> README.md
    git init
    git add .
    git commit -m "first commit"
    git branch -M main
    git remote add origin git@github.com:ATThompson/fantasyStats-back.git
    git push -u origin main
}