package com.gwkim.security.oauth2.core.authentication.userdetails.service.form;

import com.gwkim.security.oauth2.core.authentication.dto.OAuth2Type;
import com.gwkim.security.oauth2.domain.Member;
import com.gwkim.security.oauth2.domain.SocialTypeEnum;
import lombok.*;

@Getter @Setter
@NoArgsConstructor
public class SecurityUserSaveForm {
    String id;
    String name;
    String mobile;
    String clientType;

    @Builder
    public SecurityUserSaveForm(String id, String name, String mobile, String clientType) {
        this.id = id;
        this.name = name;
        this.mobile = mobile;
        this.clientType = clientType;
    }

    public Member createMember() {
        return Member.builder()
                .vehicleOwnerId(this.id)
                .socialId(this.id)
                .ownerNm(this.name)
                .telNo(this.mobile)
                .socialType(SocialTypeEnum.valueOf(this.clientType))
                .build();
    }
}
