package gwkim.security.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping("/author/unauthorized")
public class SecurityUnauthorizedController {

    @RequestMapping(produces = MediaType.TEXT_HTML_VALUE)
    public String unauthorizedHtml() {
        return "login";
    }

    @RequestMapping
    public ResponseEntity<String> unauthorized() {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("로그인이 필요한 서비스입니다.");
    }

}
