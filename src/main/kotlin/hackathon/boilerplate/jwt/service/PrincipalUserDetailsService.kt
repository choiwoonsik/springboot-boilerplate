package hackathon.boilerplate.jwt.service

import hackathon.boilerplate.jwt.model.PrincipalUserDetails
import hackathon.boilerplate.member.model.Member
import hackathon.boilerplate.member.repository.MemberRepository
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.core.userdetails.UsernameNotFoundException
import org.springframework.stereotype.Service

@Service
class PrincipalUserDetailsService(
    private val memberRepository: MemberRepository
) : UserDetailsService {
    private val log: Logger = LoggerFactory.getLogger(this::class.simpleName)

    @Throws(UsernameNotFoundException::class)
    override fun loadUserByUsername(username: String): UserDetails {
        log.info("<UserPrincipal 조회 후 반환>")

        val member: Member = memberRepository.findMemberByUsername(username)
            ?: throw UsernameNotFoundException("$username 회원이 존재하지 않습니다.")

        return PrincipalUserDetails(member)
    }
}