package hackathon.boilerplate.jwt.authenticationfilter

import com.google.gson.Gson
import hackathon.boilerplate.jwt.config.JwtConfig
import hackathon.boilerplate.jwt.service.JwtProviderService
import io.jsonwebtoken.ExpiredJwtException
import io.jsonwebtoken.JwtException
import org.springframework.http.HttpStatus
import org.springframework.stereotype.Component
import org.springframework.web.filter.OncePerRequestFilter
import javax.servlet.FilterChain
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

@Component
class JwtAuthorizationExceptionFilter(
    private val jwtProviderService: JwtProviderService
) : OncePerRequestFilter() {
    override fun doFilterInternal(
        request: HttpServletRequest,
        response: HttpServletResponse,
        filterChain: FilterChain
    ) {
        try {
            filterChain.doFilter(request, response) // -> CustomJwtAuthorizationFilter 진행
        } catch (ex: ExpiredJwtException) {
            setErrorResponse(response, HttpStatus.UNAUTHORIZED, JwtConfig.EXPIRED_EXCEPTION, ex)
        } catch (ex: JwtException) {
            setErrorResponse(response, HttpStatus.UNAUTHORIZED, JwtConfig.JWT_EXCEPTION, ex)
        } catch (ex: Exception) {
            setErrorResponse(response, HttpStatus.BAD_REQUEST, JwtConfig.EXCEPTION, ex)
        }
    }

    fun setErrorResponse(res: HttpServletResponse, status: HttpStatus, errorType: String, ex: Throwable) {
        jwtProviderService.setErrorResponseMessage(res, status, errorType, ex.message ?: "")
    }
}

data class JwtExceptionResponse(
    val status: HttpStatus,
    val message: String,
) {
    fun toJsonString(): String {
        return Gson().toJson(this)
    }
}