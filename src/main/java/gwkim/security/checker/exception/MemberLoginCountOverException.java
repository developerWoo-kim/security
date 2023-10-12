package gwkim.security.checker.exception;

public class MemberLoginCountOverException extends RuntimeException{
    public MemberLoginCountOverException(String message) {
        super(message);
    }
}
