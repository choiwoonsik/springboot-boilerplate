package hackathon.boilerplate.member.model

enum class RoleType {
    ROLE_USER, ROLE_ADMIN;

    companion object {
        fun find(roleName: String): RoleType? {
            return RoleType.values().firstOrNull { it.name == roleName }
        }
    }
}
