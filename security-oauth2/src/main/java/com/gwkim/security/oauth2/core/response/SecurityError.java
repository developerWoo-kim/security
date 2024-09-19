package com.gwkim.security.oauth2.core.response;

import lombok.Getter;
import org.springframework.http.HttpStatus;

@Getter
public enum SecurityError {
    CMM_SYSTEM_ERROR(HttpStatus.INTERNAL_SERVER_ERROR,"system-001","알수 없는 에러가 발생 하였습니다.\n관리자에게 문의해 주시기 바랍니다."),

    CMM_AUTH_BAD_CREDENTIALS(HttpStatus.BAD_REQUEST,"auth-001","아이디 또는 비밀번호를 잘못 입력하셨습니다.\n입력하신 내용을 다시 확인해주세요."),
    CMM_AUTH_ACCOUNT_EXPIRED(HttpStatus.NOT_ACCEPTABLE, "auth-002", "계정만료"),
    CMM_AUTH_CREDENTIALS_EXPIRED(HttpStatus.NOT_ACCEPTABLE,"auth-003", "비밀번호 변경주기가 도래하였습니다."),
    CMM_AUTH_ACCOUNT_DISABLED(HttpStatus.NOT_ACCEPTABLE,"auth-004", "계정비활성화"),
    CMM_AUTH_ACCOUNT_LOCKED(HttpStatus.NOT_ACCEPTABLE,"auth-005", ""),
    CMM_AUTH_REFRESH_TOKEN_NOT_FOUND(HttpStatus.NOT_FOUND, "auth-006", "Refresh Token이 누락 되었습니다."),
    CMM_AUTH_ACCESS_TOKEN_NOT_FOUND(HttpStatus.UNAUTHORIZED, "auth-007", "Access Token이 누락 되었습니다."),
    CMM_AUTH_ROLE_NOT_FOUND(HttpStatus.FORBIDDEN, "auth-008", "권한이 존재하지 않습니다."),
    CMM_AUTH_TOKEN_MALFORMED(HttpStatus.UNAUTHORIZED, "auth-009", "손상된 토큰입니다."),
    CMM_AUTH_TOKEN_EXPIRED(HttpStatus.UNAUTHORIZED, "auth-010", "만료된 토큰입니다."),
    CMM_AUTH_TOKEN_UNSUPPORTED(HttpStatus.UNAUTHORIZED, "auth-011", "지원하지 않는 토큰입니다."),
    CMM_AUTH_TOKEN_ILLEGAL_ARGUMENT(HttpStatus.UNAUTHORIZED, "auth-012", "시그니처 검증에 실패했습니다."),
    ;

    private HttpStatus status;
    private String code;
    private String message;

    SecurityError(HttpStatus status, String code, String message) {
        this.status = status;
        this.code = code;
        this.message = message;
    }
}
