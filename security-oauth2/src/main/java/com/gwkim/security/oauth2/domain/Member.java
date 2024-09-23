package com.gwkim.security.oauth2.domain;

import jakarta.persistence.*;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

import static jakarta.persistence.EnumType.STRING;

@Getter
@NoArgsConstructor
@Entity(name = "tb_vehicle_owner")
public class Member {
    @Id
    @Column(name = "vehicle_owner_id")
    private String vehicleOwnerId;
    private String socialId;

    @Enumerated(STRING)
    private SocialTypeEnum socialType;

    private String ownerNm;
    private String telNo;
    private String zipCode;
    private String addr;
    private String addrDetail;
    private String depositorNm;
    private String accountNo;
    private LocalDateTime regDateTime;
    private LocalDateTime modDateTIme;

    @Builder
    public Member(String vehicleOwnerId, String socialId, SocialTypeEnum socialType, String ownerNm, String telNo, String zipCode, String addr, String addrDetail, String depositorNm, String accountNo, LocalDateTime regDateTime, LocalDateTime modDateTIme) {
        this.vehicleOwnerId = vehicleOwnerId;
        this.socialId = socialId;
        this.socialType = socialType;
        this.ownerNm = ownerNm;
        this.telNo = telNo;
        this.zipCode = zipCode;
        this.addr = addr;
        this.addrDetail = addrDetail;
        this.depositorNm = depositorNm;
        this.accountNo = accountNo;
        this.regDateTime = regDateTime;
        this.modDateTIme = modDateTIme;
    }
}
