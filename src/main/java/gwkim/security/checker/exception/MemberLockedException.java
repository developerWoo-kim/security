package gwkim.security.checker.exception;

public class MemberLockedException extends RuntimeException{
    public MemberLockedException(String message) {
        super(message);
    }
}
