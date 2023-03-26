package hackathon.boilerplate.member.repository

import hackathon.boilerplate.member.model.Role
import hackathon.boilerplate.member.model.RoleType
import org.springframework.data.jpa.repository.JpaRepository

interface RoleJpaRepository : JpaRepository<Role, Long> {
    fun findByRoleType(roleType: RoleType): Role?
}