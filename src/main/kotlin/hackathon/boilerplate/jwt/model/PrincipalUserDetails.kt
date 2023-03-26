package hackathon.boilerplate.jwt.model

import hackathon.boilerplate.member.model.Member
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.userdetails.UserDetails

data class PrincipalUserDetails(
    private val member: Member
) : UserDetails {

    override fun getAuthorities(): MutableCollection<out GrantedAuthority> {
        val authorities: MutableList<GrantedAuthority> = mutableListOf()
        member.getRoleTypeList().map {
            authorities.add(GrantedAuthority { it.name })
        }
        return authorities
    }

    override fun getPassword() = member.password
    override fun getUsername() = member.username
    override fun isAccountNonExpired() = true
    override fun isAccountNonLocked() = true
    override fun isCredentialsNonExpired() = true
    override fun isEnabled() = true
}