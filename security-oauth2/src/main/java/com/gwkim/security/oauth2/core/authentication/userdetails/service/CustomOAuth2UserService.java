package com.gwkim.security.oauth2.core.authentication.userdetails.service;

import com.gwkim.security.oauth2.core.authentication.dto.OAuth2Type;
import com.gwkim.security.oauth2.core.authentication.userdetails.CustomOAuth2User;
import com.gwkim.security.oauth2.core.authentication.userdetails.OAuth2UserInfo;
import com.gwkim.security.oauth2.core.authentication.userdetails.SecurityUser;
import com.gwkim.security.oauth2.core.authentication.userdetails.service.form.SecurityUserSaveForm;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.HashMap;
import java.util.Map;

@Service
@Transactional
@RequiredArgsConstructor
public class CustomOAuth2UserService {
    private final SecurityUserUseCase securityUserUseCase;

    public CustomOAuth2User loadUserByUsername(OAuth2UserInfo oAuth2UserInfo) throws UsernameNotFoundException {
        SecurityUser findUser = securityUserUseCase.findById(oAuth2UserInfo.id());

        if(findUser == null) {
            SecurityUserSaveForm build = new SecurityUserSaveForm().builder()
                    .id(oAuth2UserInfo.id())
                    .name(oAuth2UserInfo.name())
                    .mobile(oAuth2UserInfo.mobile())
                    .clientType(oAuth2UserInfo.clientType())
                    .build();

            securityUserUseCase.save(build);
        }

        return new CustomOAuth2User(oAuth2UserInfo);
    }
}
