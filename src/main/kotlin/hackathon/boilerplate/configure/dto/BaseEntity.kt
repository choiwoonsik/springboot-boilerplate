package hackathon.boilerplate.configure.dto

import org.hibernate.envers.Audited
import org.springframework.data.annotation.CreatedBy
import org.springframework.data.annotation.CreatedDate
import org.springframework.data.annotation.LastModifiedBy
import org.springframework.data.annotation.LastModifiedDate
import org.springframework.data.jpa.domain.support.AuditingEntityListener
import java.time.LocalDateTime
import javax.persistence.Column
import javax.persistence.EntityListeners
import javax.persistence.MappedSuperclass

@MappedSuperclass
@EntityListeners(AuditingEntityListener::class)
@Audited(withModifiedFlag = true)
class BaseEntity : BaseTimeEntity() {
    @CreatedBy
    @LastModifiedBy
    var auditor: String = ""
}

@MappedSuperclass
@EntityListeners(AuditingEntityListener::class)
@Audited(withModifiedFlag = true)
class BaseTimeEntity {
    @CreatedDate
    @Column(updatable = false)
    var dateCreated: LocalDateTime? = null

    @LastModifiedDate
    var dateUpdated: LocalDateTime? = null
}

typealias ID = String