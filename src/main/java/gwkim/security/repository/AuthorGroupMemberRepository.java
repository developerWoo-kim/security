package gwkim.security.repository;

import gwkim.security.domain.AuthorGroupMember;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AuthorGroupMemberRepository extends JpaRepository<AuthorGroupMember, Long> {
}
