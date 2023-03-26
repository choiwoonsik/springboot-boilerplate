package hackathon.boilerplate.jwt.dto

enum class JwtErrorCode(
    private val message: String
) {
    JWT_VALID_TOKEN("정상 토큰")
    , JWT_ACCESS_NOT_VALID("엑세스 토큰이 유효하지 않습니다.")
    , JWT_REFRESH_NOT_VALID("리프레쉬 토큰이 유효하지 않습니다.")
    , JWT_ACCESS_EXPIRED("엑세스 토큰이 만료되었습니다.")
    , JWT_REFRESH_EXPIRED("토큰이 만료되었습니다. 다시 로그인 해주세요.")
    , JWT_NOT_VALID("토큰이 유효하지 않습니다.")
    , JWT_HEADER_NOT_VALID("헤더가 유효하지 않습니다.")
    , JWT_MEMBER_NOT_FOUND_TOKEN("토큰에 해당하는 회원이 없습니다.")
    , JWT_MEMBER_NOT_FOUND_USERNAME("username에 해당하는 회원이 없습니다.")
}