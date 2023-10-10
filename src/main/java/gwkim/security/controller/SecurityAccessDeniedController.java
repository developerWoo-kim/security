package gwkim.security.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping("/author")
public class SecurityAccessDeniedController {
    @RequestMapping(name = "/denied",produces = MediaType.TEXT_HTML_VALUE)
    public String failedSecureHtml() {
        return "403";
    }

    @RequestMapping(name = "/denied")
    public ResponseEntity<String> failedSecure() {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(null);
    }
}
