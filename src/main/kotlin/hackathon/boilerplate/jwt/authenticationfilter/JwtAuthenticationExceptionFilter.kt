package hackathon.boilerplate.jwt.authenticationfilter

import com.google.gson.Gson
import hackathon.boilerplate.jwt.config.JwtConfig
import io.jsonwebtoken.JwtException
import org.springframework.http.HttpStatus
import org.springframework.stereotype.Component
import org.springframework.web.filter.OncePerRequestFilter
import javax.servlet.FilterChain
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

@Component
class JwtAuthenticationExceptionFilter : OncePerRequestFilter() {
    override fun doFilterInternal(
        request: HttpServletRequest,
        response: HttpServletResponse,
        filterChain: FilterChain
    ) {
        try {
            filterChain.doFilter(request, response) // -> CustomJwtAuthenticationFilter 진행
        } catch (ex: JwtException) {
            setErrorResponse(HttpStatus.UNAUTHORIZED, response, ex)
        }
    }

    fun setErrorResponse(status: HttpStatus, res: HttpServletResponse, ex: Throwable) {
        res.status = status.value()
        res.contentType = "application/json; charset=UTF-8"
        res.writer.write(JwtExceptionResponse(status, "${JwtConfig.EXPIRED_EXCEPTION}_${ex.message}").toJsonString())
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