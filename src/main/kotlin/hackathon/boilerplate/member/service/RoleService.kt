package hackathon.boilerplate.member.service

import hackathon.boilerplate.member.model.Role
import hackathon.boilerplate.member.model.RoleType
import hackathon.boilerplate.member.repository.RoleJpaRepository
import org.springframework.security.access.AuthorizationServiceException
import org.springframework.stereotype.Service

@Service
class RoleService(
    private val roleJpaRepository: RoleJpaRepository
) {
    fun findRole(roleType: RoleType): Role {
        return roleJpaRepository.findByRoleType(roleType)
            ?: throw AuthorizationServiceException("해당하는 권한이 없습니다.")
    }
}