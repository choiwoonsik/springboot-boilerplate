package hackathon.boilerplate.configure

import hackathon.boilerplate.configure.dto.ErrorCode
import org.springframework.security.core.AuthenticationException

open class CustomRuntimeException(
    open val errorCode: ErrorCode,
    msg: String?,
) : RuntimeException(msg)

/** 찾고자 하는 리소스가 없는 경우 */
data class DataNotFoundException(
    override val errorCode: ErrorCode,
    val msg: String? = null
) : CustomRuntimeException(errorCode, msg)

/** 클라이언트에서 넘겨받은 파라미터가 유효하지 않은 경우 */
data class ParameterInvalidException(
    override val errorCode: ErrorCode,
    val msg: String? = null
) : CustomRuntimeException(errorCode, msg)

data class JwtProviderException(
    val msg: String? = null
) : AuthenticationException(msg)
