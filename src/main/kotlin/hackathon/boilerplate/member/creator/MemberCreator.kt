package hackathon.boilerplate.member.creator

import com.netflix.dgs.codegen.generated.types.CreateMemberInput
import hackathon.boilerplate.member.model.Member
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.stereotype.Component

@Component
class MemberCreator(
    private val passwordEncoder: BCryptPasswordEncoder,
) {
    fun createMember(input: CreateMemberInput): Member {
        val encodePassword = passwordEncoder.encode(input.password)
        return Member(
            username = input.username,
            password = encodePassword,
            token = "",
            profileName = input.profile_name,
            roleListString = ""
        )
    }
}