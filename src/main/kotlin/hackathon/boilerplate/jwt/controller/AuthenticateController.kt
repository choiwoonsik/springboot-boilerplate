package hackathon.boilerplate.jwt.controller

import com.netflix.dgs.codegen.generated.types.CreateMemberInput
import com.netflix.dgs.codegen.generated.types.LoginInput
import hackathon.boilerplate.member.service.MemberService
import io.swagger.annotations.Api
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RestController

@RestController
@Api("Auth")
class AuthenticateController(
    private val memberService: MemberService
) {
    @PostMapping("/api/v1/login")
    fun memberLogin(@RequestBody input: LoginInput): ResponseEntity<String> {
        return ResponseEntity
            .status(HttpStatus.OK)
            .body("성공")
    }

    @PostMapping("/api/v1/signUp")
    fun memberSignUp(@RequestBody input: CreateMemberInput): ResponseEntity<ResponseData<Long>> {
        val memberId = memberService.create(input)
        return ResponseEntity
            .status(HttpStatus.OK)
            .body(ResponseData(true, "성공", memberId))
    }
}

data class ResponseData<T>(
    val success: Boolean,
    val message: String,
    val data: T
)