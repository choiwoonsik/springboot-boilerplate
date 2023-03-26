package hackathon.boilerplate.member.repository

import hackathon.boilerplate.member.model.Member
import org.springframework.data.jpa.repository.JpaRepository

interface MemberJpaRepository : JpaRepository<Member, Long> {
    fun findMemberByToken(token: String): Member?
}