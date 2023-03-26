package hackathon.boilerplate.configure

import hackathon.boilerplate.configure.dto.ErrorCode

/** 찾고자 하는 리소스가 없는 경우 */
data class DataNotFoundException(
    override val errorCode: ErrorCode,
    val msg: String = "",
    val throwable: Throwable? = null
) : CustomClientException(errorCode, msg, throwable)

/** 클라이언트에서 넘겨받은 파라미터가 유효하지 않은 경우 */
data class ParameterInvalidException(
    override val errorCode: ErrorCode,
    val msg: String,
    val throwable: Throwable? = null
) : CustomClientException(errorCode, msg, throwable)

/** 4xx 클라이언트 에러 부모 class */
open class CustomClientException(
    open val errorCode: ErrorCode,
    msg: String,
    throwable: Throwable? = null
) : RuntimeException(msg, throwable)
