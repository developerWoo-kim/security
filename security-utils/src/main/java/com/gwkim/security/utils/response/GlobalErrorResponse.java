package com.gwkim.security.utils.response;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.*;
import org.springframework.validation.FieldError;

import java.util.ArrayList;
import java.util.List;

@Getter
@Setter
@NoArgsConstructor
public class GlobalErrorResponse {
    private String code;
    private String message;
    private String path;

    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    private List<ValidationError> errors = new ArrayList<>();

    public GlobalErrorResponse(String code, String message, String path, List<ValidationError> errors) {
        this.code = code;
        this.message = message;
        this.path = path;
        this.errors = errors;
    }

    public GlobalErrorResponse(String code, String message, String path) {
        this.code = code;
        this.message = message;
        this.path = path;
    }

    @Getter
    @Builder
    @RequiredArgsConstructor
    public static class ValidationError {
        private final String field;
        private final String message;
        public static ValidationError of(final FieldError fieldError) {
            return ValidationError.builder()
                    .field(fieldError.getField())
                    .message(fieldError.getDefaultMessage())
                    .build();


        }
    }
}
