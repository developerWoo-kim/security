package com.gwkim.security.basic.core.authorization;

import com.neoclue.adruck.api.common.security.core.userdetails.CustomUserDetails;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

/**
 *	Class Name	: AuthorizationChecker.java
 *	Description	: 클라이언트 요청에 대한 인가 여부를 확인
 *                 - ignore uri을 제외한 모든 요청의 인가 여부를 확인
 *
 *	Modification Information
 *	수정일		수정자		수정 내용
 *	-----------	----------	---------------------------
 *	2023.10.24	gwkim		최초 생성
 *  2023.10.31	gwkim		메뉴 권한 체킹 로직 단순화, SecurityAuthorUtil
 *
 *
 *	@author  gwkim
 *	@since  2023.10.24
 *	@version 1.1
 */
@Component
@Transactional
@RequiredArgsConstructor
public class AuthorizationChecker {

    public boolean check(HttpServletRequest request, Authentication authentication) {
        String url = request.getRequestURI();
        String method = request.getMethod();
        CustomUserDetails userDetails = (CustomUserDetails) authentication.getPrincipal();

        return true;
    }

}
