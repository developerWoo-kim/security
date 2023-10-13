package gwkim.security.exception;

import org.springframework.security.authentication.*;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;


public class AuthenticationMessageProvider {
    public static AuthenticationExceptionTypes getExceptionMessage(AuthenticationException exception) {
        return AuthenticationExceptionTypes.findOf(exception.getClass().getSimpleName());
    }
}
