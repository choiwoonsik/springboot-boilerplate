package hackathon.boilerplate.member.controller

import com.netflix.dgs.codegen.generated.types.CreateMemberInput
import com.netflix.dgs.codegen.generated.types.MemberResponse
import com.netflix.dgs.codegen.generated.types.UpdateProfileNameInput
import com.netflix.graphql.dgs.DgsComponent
import com.netflix.graphql.dgs.DgsMutation
import com.netflix.graphql.dgs.DgsQuery
import com.netflix.graphql.dgs.InputArgument
import hackathon.boilerplate.configure.dto.ID
import hackathon.boilerplate.member.service.MemberService
import org.springframework.security.access.prepost.PreAuthorize

@DgsComponent
class MemberFetcher(
    private val memberService: MemberService,
) {
    @DgsQuery
    @PreAuthorize("hasRole('USER')")
    fun getQueryUserAuth(): Boolean {
        return true
    }

    @DgsQuery
    @PreAuthorize("hasRole('ADMIN')")
    fun getQueryAdminAuth(): Boolean {
        return true
    }

    @DgsQuery
    fun getQueryAnonymousAuth(): Boolean {
        return true
    }

    @DgsQuery
    @PreAuthorize("hasAnyRole('USER', 'ADMIN')")
    fun getMember(
        @InputArgument(name = "member_id") memberId: ID
    ): MemberResponse {
        return memberService.findMemberById(memberId.toLong())
    }

    @DgsQuery
    fun getAllMemberList(): List<MemberResponse> {
        return memberService.findAllMember()
    }

    @DgsMutation
    fun createMember(
        @InputArgument input: CreateMemberInput
    ): Long {
        return memberService.create(input)
    }

    @DgsMutation
    @PreAuthorize("hasAnyRole('USER', 'ADMIN')")
    fun updateProfileName(
        @InputArgument input: UpdateProfileNameInput
    ): Long {
        return memberService.updateProfileName(input)
    }
}