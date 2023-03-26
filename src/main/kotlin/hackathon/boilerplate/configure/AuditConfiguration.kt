package hackathon.boilerplate.configure

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.data.auditing.DateTimeProvider
import org.springframework.data.domain.AuditorAware
import org.springframework.data.jpa.repository.config.EnableJpaAuditing
import org.springframework.web.context.request.RequestContextHolder
import org.springframework.web.context.request.ServletRequestAttributes
import java.time.OffsetDateTime
import java.util.*

@Configuration
@EnableJpaAuditing(dateTimeProviderRef = "auditingDateTimeProvider")
class AuditConfiguration {
    @Bean
    fun auditorAware(): AuditorAware<*> {
        return AuditorAwareImpl()
    }

    @Bean
    fun auditingDateTimeProvider(): DateTimeProvider {
        return DateTimeProvider { Optional.of(OffsetDateTime.now()) }
    }
}

class AuditorAwareImpl : AuditorAware<String> {

    companion object {
        private const val DEFAULT_AUDITOR = "DEFAULT_AUDITOR"
    }

    override fun getCurrentAuditor(): Optional<String> {
        if (RequestContextHolder.getRequestAttributes() == null) {
            return Optional.of(DEFAULT_AUDITOR)
        }

        val request = (RequestContextHolder.getRequestAttributes() as ServletRequestAttributes).request
        val auditor = request.getAttribute("auditor")

        return if (auditor == null) {
            Optional.of(DEFAULT_AUDITOR)
        } else {
            Optional.of(auditor as String)
        }
    }
}