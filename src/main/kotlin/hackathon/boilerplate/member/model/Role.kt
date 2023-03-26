package hackathon.boilerplate.member.model

import org.hibernate.envers.Audited
import javax.persistence.Column
import javax.persistence.Entity
import javax.persistence.EnumType
import javax.persistence.Enumerated
import javax.persistence.GeneratedValue
import javax.persistence.GenerationType
import javax.persistence.Id

@Entity
@Audited
class Role(
    @Column(nullable = false) @Enumerated(value = EnumType.STRING) val roleType: RoleType,
    @Id @GeneratedValue(strategy = GenerationType.IDENTITY) val id: Long = 0L,
)