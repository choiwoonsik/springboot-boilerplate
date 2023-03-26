package hackathon.boilerplate.jwt.authenticationfilter

import hackathon.boilerplate.jwt.config.JwtConfig
import hackathon.boilerplate.jwt.model.PrincipalUserDetails
import hackathon.boilerplate.jwt.service.JwtProviderService
import io.jsonwebtoken.ExpiredJwtException
import io.jsonwebtoken.JwtException
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.springframework.http.HttpStatus
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.stereotype.Component
import org.springframework.web.filter.OncePerRequestFilter
import javax.servlet.FilterChain
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

@Component
class CustomJwtAuthorizationFilter(
    private val jwtProviderService: JwtProviderService,
) : OncePerRequestFilter() {
    private val log: Logger = LoggerFactory.getLogger(this::class.simpleName)

    override fun doFilterInternal(
        request: HttpServletRequest,
        response: HttpServletResponse,
        filterChain: FilterChain
    ) {
        log.info("<Authorization(인가) 필터>")
        try {
            request
                .apply {
                    if (checkValidHeader().not()) {
                        jwtProviderService.setErrorResponseMessage(
                            response = response,
                            status = HttpStatus.BAD_REQUEST,
                            errorType = JwtConfig.HEADER_EXCEPTION,
                            message = "잘못된 헤더입니다."
                        )
                        return
                    }
                }
                .let {
                    if (jwtProviderService.onlyAccessToken(request)) {
                        TokenPair(
                            jwtProviderService.extractAccessToken(request),
                            null
                        )
                    } else {
                        TokenPair(
                            jwtProviderService.extractAccessToken(request),
                            jwtProviderService.extractRefreshToken(request)
                        )
                    }
                }
                .apply { SecurityContextHolder.getContext().authentication = getAuthentication(response) }
        } catch (expiredJwtException: ExpiredJwtException) {
            throw expiredJwtException
        } catch (jwtException: JwtException) {
            throw jwtException
        } catch (e: Exception) {
            e.printStackTrace()
            throw e
        }
        filterChain.doFilter(request, response)
    }

    private fun HttpServletRequest.checkValidHeader(): Boolean {
        return (jwtProviderService.checkValidAccessHeader(this) && !jwtProviderService.checkValidRefreshHeader(this)) ||
                (jwtProviderService.checkValidAccessHeader(this) && jwtProviderService.checkValidRefreshHeader(this))
    }

    private fun TokenPair.getAuthentication(response: HttpServletResponse): UsernamePasswordAuthenticationToken {
        val principal = if (refresh == null) {
            check(jwtProviderService.checkValidToken(access))
            check(jwtProviderService.checkTokenExpired(access).not())
            val member = jwtProviderService.findMemberByAccessToken(access)
            PrincipalUserDetails(member)
        } else {
            check(jwtProviderService.checkValidToken(access))
            check(jwtProviderService.checkValidToken(refresh))
            check(jwtProviderService.checkTokenExpired(refresh).not())
            val member = jwtProviderService.findMemberByRefreshToken(refresh)
            val expireIn7Day = jwtProviderService.checkExpireInSevenDayToken(refresh)
            if (expireIn7Day) reissueRefreshToken(member.username, response)
            reissueAccessToken(member.username, response)
            PrincipalUserDetails(member)
        }

        return UsernamePasswordAuthenticationToken(principal, null, principal.authorities)
    }

    private fun reissueAccessToken(
        username: String,
        response: HttpServletResponse
    ) {
        log.info("[ACCESS TOKEN] 액세스 토큰 재발급")
        val reissuedAccessToken = jwtProviderService.createAccessToken(username)
        jwtProviderService.setHeaderOfAccessToken(response, reissuedAccessToken)
    }

    private fun reissueRefreshToken(
        username: String,
        response: HttpServletResponse
    ) {
        log.info("[REFRESH TOKEN] 리프레쉬 토큰 재발급")
        val reissuedRefreshToken = jwtProviderService.reissueRefreshToken(username)
        jwtProviderService.setHeaderOfRefreshToken(response, reissuedRefreshToken)
    }
}

data class TokenPair(
    val access: String,
    val refresh: String?,
)