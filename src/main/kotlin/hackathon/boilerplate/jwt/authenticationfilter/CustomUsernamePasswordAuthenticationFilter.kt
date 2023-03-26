package hackathon.boilerplate.jwt.authenticationfilter

import com.fasterxml.jackson.databind.ObjectMapper
import com.netflix.dgs.codegen.generated.types.LoginInput
import hackathon.boilerplate.configure.DataNotFoundException
import hackathon.boilerplate.configure.dto.ErrorCode
import hackathon.boilerplate.jwt.model.PrincipalUserDetails
import hackathon.boilerplate.jwt.service.JwtProviderService
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.Authentication
import org.springframework.security.core.AuthenticationException
import org.springframework.security.core.userdetails.UsernameNotFoundException
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter
import java.io.IOException
import javax.servlet.FilterChain
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

class CustomUsernamePasswordAuthenticationFilter(
    private val authenticationManager: AuthenticationManager,
    private val jwtProviderService: JwtProviderService
) : UsernamePasswordAuthenticationFilter() {

    private val log: Logger = LoggerFactory.getLogger(this::class.simpleName)

    override fun attemptAuthentication(
        request: HttpServletRequest,
        response: HttpServletResponse
    ): Authentication {
        log.info("<로그인 시 Authentication(인증) 시도>")
        try {
            val om = ObjectMapper()
            val loginInput = om.readValue(request.inputStream, LoginInput::class.java)
            val authentication = UsernamePasswordAuthenticationToken(loginInput.username, loginInput.password)
            return authenticationManager.authenticate(authentication)
        } catch (e: IOException) {
            e.printStackTrace()
            throw DataNotFoundException(ErrorCode.ITEM_NOT_EXIST, "회원이 존재하지 않습니다.")
        }
    }

    override fun successfulAuthentication(
        request: HttpServletRequest?,
        response: HttpServletResponse,
        chain: FilterChain?,
        authResult: Authentication?
    ) {
        log.info("[인증 성공] JWT 발급")
        val principal: PrincipalUserDetails = authResult!!.principal as PrincipalUserDetails

        val accessToken: String = jwtProviderService.createAccessToken(principal.username)
        val refreshToken: String = jwtProviderService.createRefreshToken()

        jwtProviderService.saveRefreshToken(principal.username, refreshToken)

        jwtProviderService.setHeaderOfAccessToken(response, accessToken)
        jwtProviderService.setHeaderOfRefreshToken(response, refreshToken)

        jwtProviderService.setResponseMessage(true, response, "로그인 성공")
    }

    override fun unsuccessfulAuthentication(
        request: HttpServletRequest?,
        response: HttpServletResponse,
        failed: AuthenticationException?
    ) {
        log.info("[인증 실패]")
        val failMessage = when (failed!!.message) {
            ErrorCode.ITEM_NOT_EXIST.name -> ErrorCode.ITEM_NOT_EXIST.name
            ErrorCode.WRONG_PASSWORD.name -> ErrorCode.WRONG_PASSWORD.name
            else -> ErrorCode.UNKNOWN_ERROR.name
        }
        jwtProviderService.setResponseMessage(false, response, "로그인 실패: $failMessage")
        throw UsernameNotFoundException(failMessage)
    }
}