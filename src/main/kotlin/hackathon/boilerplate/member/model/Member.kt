package hackathon.boilerplate.member.model

import hackathon.boilerplate.configure.dto.BaseEntity
import org.hibernate.envers.Audited
import java.io.Serializable
import javax.persistence.Column
import javax.persistence.Entity
import javax.persistence.GeneratedValue
import javax.persistence.GenerationType
import javax.persistence.Id

@Entity
@Audited(withModifiedFlag = true)
class Member(
    @Column(nullable = false) val username: String,
    @Column(nullable = false) val password: String,
    @Column(nullable = false) var token: String,
    @Column(nullable = false) var profileName: String,
    @Column(nullable = false) var roleListString: String,
    @Id @GeneratedValue(strategy = GenerationType.IDENTITY) val id: Long = 0L,
) : BaseEntity(), Serializable {

    fun updateToken(token: String) {
        this.token = token
    }

    fun getRoleTypeList(): List<RoleType> {
        return roleListString
            .split(",")
            .map { it.trim() }
            .mapNotNull { RoleType.find(it) }
    }

    fun addRoleType(role: RoleType) {
        this.roleListString += "${role.name},"
    }
}