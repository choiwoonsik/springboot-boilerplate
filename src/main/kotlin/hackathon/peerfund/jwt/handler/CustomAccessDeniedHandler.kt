package hackathon.peerfund.jwt.handler

import com.netflix.graphql.dgs.exceptions.DefaultDataFetcherExceptionHandler
import hackathon.peerfund.jwt.config.JwtConfig
import hackathon.peerfund.jwt.service.JwtProviderService
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.springframework.context.annotation.Bean
import org.springframework.security.access.AccessDeniedException
import org.springframework.security.web.access.AccessDeniedHandler
import org.springframework.stereotype.Component
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

@Component
class CustomAccessDeniedHandler(
    private val jwtProviderService: JwtProviderService
) : AccessDeniedHandler {
    private val log: Logger = LoggerFactory.getLogger(this::class.simpleName)

    override fun handle(
        request: HttpServletRequest,
        response: HttpServletResponse,
        accessDeniedException: AccessDeniedException
    ) {
        log.error("[권한 오류] ${accessDeniedException.message}");
        val exceptionMessage = request.getAttribute(JwtConfig.EXCEPTION).toString()
        jwtProviderService.setResponseMessage(false, response, exceptionMessage)
    }
}

@Bean
fun customGraphqlAccessDeniedHandler(): DefaultDataFetcherExceptionHandler {
    try {
        return DefaultDataFetcherExceptionHandler()
    } catch (e: Exception) {
        println("권한 오류")
        throw AccessDeniedException("권한 오류")
    }
}