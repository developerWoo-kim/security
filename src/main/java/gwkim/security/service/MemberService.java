package gwkim.security.service;

import gwkim.security.domain.LoginPreventStatus;
import gwkim.security.domain.Member;
import gwkim.security.repository.MemberRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional
@RequiredArgsConstructor
public class MemberService {
    private final MemberRepository memberRepository;

    @Value("${security.login.fail.imsi-lock.max-count}")
    private Integer imsiLockMaxCount;

    /**
     * 로그인 시도 횟수 증가
     * @param memberId 회원 아이디
     */
    public void incrementLoginFailCount(String memberId) {
        Member member = memberRepository.findById(memberId).orElseThrow();
        // 로그인 시도 횟수 증가
        member.incrementLoginFailCount();
        // 로그인 최대 시도 횟수에 도달하면 계정 잠금
        if(member.getLoginCnt() >= imsiLockMaxCount) {
            member.setLoginPreventStatus(LoginPreventStatus.LOCKED);
        }
    }

    /**
     * 로그인 시도 횟수 초기화
     * @param memberId 회원 아이디
     */
    public void resetLoginFailCount(String memberId) {
        Member member = memberRepository.findById(memberId).orElseThrow();
        // 로그인 시도 횟수 초기화
        member.resetLoginFailCount();
    }
}
