package hackathon.boilerplate.configure

import org.aspectj.lang.annotation.Aspect
import org.aspectj.lang.annotation.Before
import org.springframework.stereotype.Component
import org.springframework.web.context.request.RequestContextHolder
import org.springframework.web.context.request.ServletRequestAttributes
import javax.servlet.http.HttpServletRequest
import kotlin.reflect.full.memberProperties

@Component
@Aspect
class AuditorAspect {
    @Before("execution(* hackathon.boilerplate.*.*.*Fetcher.*(..)) &&" + "args(input)")
    fun setAuditor(input: Any) {
        val req: HttpServletRequest = (RequestContextHolder.getRequestAttributes() as ServletRequestAttributes).request
        val auditor = input.javaClass.kotlin.memberProperties.find { it.name == "auditor" }?.get(input) as String?
        if (auditor != null) {
            req.setAttribute("auditor", auditor)
        }
    }
}