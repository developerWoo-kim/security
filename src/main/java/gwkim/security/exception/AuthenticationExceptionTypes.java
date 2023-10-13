package gwkim.security.exception;

import lombok.Getter;

import java.util.Collections;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Getter
public enum AuthenticationExceptionTypes {
    BadCredentialsException("아이디 또는 비밀번호를 잘못 입력하셨습니다.\n입력하신 내용을 다시 확인해주세요."),
    UsernameNotFoundException("아이디 또는 비밀번호를 잘못 입력하셨습니다.\n입력하신 내용을 다시 확인해주세요."),
    AccountExpiredException("계정만료"),
    CredentialsExpiredException("비밀번호 변경주기가 도래하였습니다."),
    DisabledException("계정비활성화"),
    LockedException("잘못된 5회 로그인 시도로 인해 계정이 잠겼습니다."),
    NoneException("알 수 없는 에러가 발생 하였습니다.\n관리자에게 문의해 주시기 바랍니다.");

    private String value;

    AuthenticationExceptionTypes(String value) {
        this.value = value;
    }

    private static final Map<String, AuthenticationExceptionTypes> descriptions = Collections
            .unmodifiableMap(Stream.of(values())
                            .collect(Collectors.toMap(AuthenticationExceptionTypes::name, Function.identity())));

    public static AuthenticationExceptionTypes findOf(String findValue) {
        return Optional.ofNullable(descriptions.get(findValue)).orElse(NoneException);
    }
}
