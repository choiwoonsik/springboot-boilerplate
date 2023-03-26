package hackathon.boilerplate.jwt.handler

import hackathon.boilerplate.jwt.config.JwtConfig
import hackathon.boilerplate.jwt.service.JwtProviderService
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.springframework.security.core.AuthenticationException
import org.springframework.security.web.AuthenticationEntryPoint
import org.springframework.stereotype.Component
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

@Component
class CustomAuthenticationEntryPoint(
    private val jwtProviderService: JwtProviderService
) : AuthenticationEntryPoint {
    private val log: Logger = LoggerFactory.getLogger(this::class.simpleName)

    override fun commence(
        request: HttpServletRequest,
        response: HttpServletResponse,
        authException: AuthenticationException
    ) {
        log.warn("[인증 오류] ${authException.message}")
        val exceptionMessage = request.getAttribute(JwtConfig.EXCEPTION).toString()
        jwtProviderService.setResponseMessage(false, response, exceptionMessage)
    }
}