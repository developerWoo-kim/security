package com.gwkim.security.basic.port.in;

import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.ArrayList;
import java.util.List;

@Data
@NoArgsConstructor
public class SecurityMemberDto {
    private String memberId;
    private String memberNm;
    private String password;
    private String email;
    private String telNo;
    private String zipCode;
    private String addr;
    private String addrDetail;
    private String delYn;

    List<String> roleList = new ArrayList<>();

    @Builder
    public SecurityMemberDto(String memberId, String memberNm, String password, String email, String telNo, String zipCode, String addr, String addrDetail, String delYn) {
        this.memberId = memberId;
        this.memberNm = memberNm;
        this.password = password;
        this.email = email;
        this.telNo = telNo;
        this.zipCode = zipCode;
        this.addr = addr;
        this.addrDetail = addrDetail;
        this.delYn = delYn;
    }

    public void addRole(String roleId) {
        this.roleList.add(roleId);
    };
}
