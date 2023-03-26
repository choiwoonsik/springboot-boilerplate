package hackathon.boilerplate.member.repository

import hackathon.boilerplate.member.model.Member
import hackathon.boilerplate.member.model.QMember.member
import org.springframework.data.jpa.repository.support.QuerydslRepositorySupport
import org.springframework.stereotype.Repository
import javax.persistence.EntityManager
import javax.persistence.PersistenceContext

@Repository
class MemberRepository(
    memberJpaRepository: MemberJpaRepository
) : QuerydslRepositorySupport(Member::class.java), MemberJpaRepository by memberJpaRepository {

    @PersistenceContext
    override fun setEntityManager(entityManager: EntityManager) {
        super.setEntityManager(entityManager)
    }

    fun findMemberById(id: Long): Member? {
        return from(member)
            .where(member.id.eq(id))
            .fetchOne()
    }

    fun findMemberByUsername(username: String): Member? {
        return from(member)
            .where(member.username.eq(username))
            .fetchOne()
    }

    fun findMember(id: Long): Member {
        return from(member)
            .where(member.id.eq(id))
            .fetchOne()
    }

    fun findAllMember(): List<Member> {
        return from(member)
            .orderBy(member.dateCreated.desc())
            .fetch()
    }
}