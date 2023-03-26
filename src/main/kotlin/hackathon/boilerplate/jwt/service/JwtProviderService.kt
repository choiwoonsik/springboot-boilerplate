package hackathon.boilerplate.jwt.service

import hackathon.boilerplate.jwt.authenticationfilter.JwtExceptionResponse
import hackathon.boilerplate.jwt.config.JwtConfig
import hackathon.boilerplate.member.model.Member
import hackathon.boilerplate.member.service.MemberService
import hackathon.boilerplate.util.currentKSTDate
import hackathon.boilerplate.util.plusKSTDate
import io.jsonwebtoken.ExpiredJwtException
import io.jsonwebtoken.JwtException
import io.jsonwebtoken.JwtParser
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.security.Keys
import net.minidev.json.JSONObject
import org.springframework.beans.factory.annotation.Value
import org.springframework.http.HttpStatus
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional
import org.springframework.util.StringUtils
import java.util.*
import javax.crypto.SecretKey
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

@Service
class JwtProviderService(
    private val memberService: MemberService
) {
    @Value("\${jwt.secret-key}")
    private val secretValue: String? = null
    private fun getSecretKey(): SecretKey = Keys.hmacShaKeyFor(secretValue!!.encodeToByteArray())
    private fun getParser(): JwtParser = Jwts.parserBuilder().setSigningKey(getSecretKey()).build()
    private fun parseToken(token: String) = getParser().parseClaimsJws(token)

    fun createAccessToken(username: String): String {
        return Jwts
            .builder()
            .setSubject(JwtConfig.ACCESS)
            .setClaims(mapOf(JwtConfig.USERNAME to username))
            .setIssuedAt(currentKSTDate())
            .setExpiration(plusKSTDate(min = JwtConfig.ACCESS_TOKEN_EXPIRATION))
            .signWith(getSecretKey())
            .compact()
    }

    fun createRefreshToken(): String {
        return Jwts
            .builder()
            .setSubject(JwtConfig.REFRESH)
            .setIssuedAt(currentKSTDate())
            .setExpiration(plusKSTDate(day = JwtConfig.REFRESH_TOKEN_EXPIRATION))
            .signWith(getSecretKey())
            .compact()
    }

    fun onlyAccessToken(request: HttpServletRequest): Boolean {
        return StringUtils.hasText(request.getHeader(JwtConfig.ACCESS_TOKEN_HEADER)) &&
                StringUtils.hasText(request.getHeader(JwtConfig.REFRESH_TOKEN_HEADER)).not()
    }

    fun checkValidAccessHeader(request: HttpServletRequest): Boolean {
        request
            .apply { getHeader(JwtConfig.ACCESS_TOKEN_HEADER)?.startsWith(JwtConfig.TOKEN_PREFIX) ?: return false }
        return true
    }

    fun checkValidRefreshHeader(request: HttpServletRequest): Boolean {
        request
            .apply { getHeader(JwtConfig.REFRESH_TOKEN_HEADER)?.startsWith(JwtConfig.TOKEN_PREFIX) ?: return false }
        return true
    }

    fun extractAccessToken(request: HttpServletRequest): String {
        return request
            .getHeader(JwtConfig.ACCESS_TOKEN_HEADER)
            .replace(JwtConfig.TOKEN_PREFIX, "")
    }

    fun extractRefreshToken(request: HttpServletRequest): String {
        return request
            .getHeader(JwtConfig.REFRESH_TOKEN_HEADER)
            .replace(JwtConfig.TOKEN_PREFIX, "")
    }

    fun checkValidToken(token: String): Boolean {
        return try {
            parseToken(token).body
            true
        } catch (e: ExpiredJwtException) {
            true
        } catch (e: JwtException) {
            false
        }
    }

    fun checkTokenExpired(token: String): Boolean {
        return try {
            parseToken(token).body
            false
        } catch (e: ExpiredJwtException) {
            throw e
        }
    }

    fun checkExpireInSevenDayToken(token: String): Boolean {
        return parseToken(token).body.expiration.before(plusKSTDate(day = 7))
    }

    fun getUsername(token: String): String {
        return parseToken(token).body[JwtConfig.USERNAME].toString()
    }

    fun findMemberByRefreshToken(refreshToken: String): Member {
        return memberService.findMemberByToken(refreshToken)
    }

    fun findMemberByAccessToken(accessToken: String): Member {
        return memberService.findMemberByUsername(getUsername(accessToken))
    }

    @Transactional
    fun saveRefreshToken(username: String, token: String) {
        memberService
            .findMemberByUsername(username)
            .updateToken(token)
    }

    @Transactional
    fun reissueRefreshToken(username: String): String {
        val reissuedRefreshToken = createRefreshToken()
        memberService
            .findMemberByUsername(username)
            .updateToken(reissuedRefreshToken)
        return reissuedRefreshToken

    }

    fun setResponseMessage(result: Boolean, response: HttpServletResponse, message: String) {
        response.contentType = "application/json;charset=UTF-8"
        val content = JSONObject()
            .apply { put("success", result) }
            .apply { put("message", message) }
        response
            .writer
            .print(content)
    }

    fun setHeaderOfAccessToken(response: HttpServletResponse, token: String) {
        response.addHeader(JwtConfig.ACCESS_TOKEN_HEADER, JwtConfig.TOKEN_PREFIX + token)
    }

    fun setHeaderOfRefreshToken(response: HttpServletResponse, token: String) {
        response.addHeader(JwtConfig.REFRESH_TOKEN_HEADER, JwtConfig.TOKEN_PREFIX + token)
    }

    fun setErrorResponseMessage(response: HttpServletResponse, status: HttpStatus, errorType: String, message: String) {
        response.status = status.value()
        response.contentType = "application/json; charset=UTF-8"
        response.writer.write(JwtExceptionResponse(status, "$errorType: $message").toJsonString())
    }
}