package hackathon.boilerplate.configure

import hackathon.boilerplate.configure.dto.ErrorCode
import org.slf4j.LoggerFactory
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.ControllerAdvice
import org.springframework.web.bind.annotation.ExceptionHandler
import org.springframework.web.bind.annotation.ResponseStatus
import javax.servlet.http.HttpServletRequest

@ControllerAdvice
class GlobalExceptionHandler {
    private val logger = LoggerFactory.getLogger(this::class.simpleName)

    @ResponseStatus(HttpStatus.BAD_REQUEST)
    @ExceptionHandler(CustomRuntimeException::class)
    fun handleCustomException(
        ex: CustomRuntimeException,
        request: HttpServletRequest,
    ): ResponseEntity<ErrorResponse> {
        logger.error(
            """
            ========================================ERROR START========================================
            요청 URL: [${request.method} ${request.requestURI}]
            예외 메시지: ${ex.message}
            에러 출력: ${ex.printStackTrace()}
            ========================================ERROR END ==========================================
        """.trimIndent()
        )
        val errorResponse = ErrorResponse(ex.errorCode, ex.message ?: "")
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errorResponse)
    }
}

data class ErrorResponse(val errorCode: ErrorCode, val errorMessage: String)