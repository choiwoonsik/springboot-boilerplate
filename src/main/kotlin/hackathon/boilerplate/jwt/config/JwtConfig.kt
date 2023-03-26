package hackathon.boilerplate.jwt.config

interface JwtConfig {
    companion object {
        const val ACCESS = "AccessToken"
        const val REFRESH = "RefreshToken"
        const val EXCEPTION = "EXCEPTION"
        const val EXPIRED_EXCEPTION = "EXPIRED_EXCEPTION"
        const val USERNAME = "USERNAME"
        const val ACCESS_TOKEN_HEADER = "Authorization"
        const val REFRESH_TOKEN_HEADER = "Authorization-refresh"
        const val TOKEN_PREFIX = "Bearer "
        const val STRENGTH = 10
        const val ACCESS_TOKEN_EXPIRATION = 1L // 30min
        const val REFRESH_TOKEN_EXPIRATION = 14L // 14day
    }
}