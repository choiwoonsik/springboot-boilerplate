package hackathon.boilerplate.jwt.config

import hackathon.boilerplate.jwt.authenticationfilter.CustomJwtAuthorizationFilter
import hackathon.boilerplate.jwt.authenticationfilter.CustomUsernamePasswordAuthenticationFilter
import hackathon.boilerplate.jwt.authenticationfilter.JwtAuthorizationExceptionFilter
import hackathon.boilerplate.jwt.filter.corsFilter
import hackathon.boilerplate.jwt.handler.CustomAccessDeniedHandler
import hackathon.boilerplate.jwt.handler.CustomAuthenticationEntryPoint
import hackathon.boilerplate.jwt.service.JwtProviderService
import hackathon.boilerplate.jwt.service.PrincipalUserDetailsService
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.dao.DaoAuthenticationProvider
import org.springframework.security.config.Customizer
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer
import org.springframework.security.config.http.SessionCreationPolicy
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter

@Configuration
@EnableWebSecurity
@EnableMethodSecurity(securedEnabled = true)
class SecurityConfig(
    private val passwordEncoder: BCryptPasswordEncoder,
    private val authenticationConfiguration: AuthenticationConfiguration,
    private val jwtProviderService: JwtProviderService,
    private val principalUserDetailsService: PrincipalUserDetailsService,
    private val customAuthenticationEntryPoint: CustomAuthenticationEntryPoint,
    private val customAccessDeniedHandler: CustomAccessDeniedHandler,
    private val jwtAuthorizationExceptionFilter: JwtAuthorizationExceptionFilter,
    private val customJwtAuthorizationFilter: CustomJwtAuthorizationFilter,
) {
    @Bean
    fun webSecurityCustomizer(): WebSecurityCustomizer {
        return WebSecurityCustomizer {
            it.ignoring()
                .antMatchers(
                    "/swagger-resources/**",
                    "/swagger-ui.html",
                    "/swagger/**",
                    "/webjars/**",
                )
            it.ignoring()
                .antMatchers("/api/v1/signUp") // 회원가입 필터 제외
                .antMatchers("/playground")
        }
    }

    @Bean
    fun filterChain(http: HttpSecurity): SecurityFilterChain {
        http
            // JWT 방식의 무상태 인증/인가 처리를 적용하므로 세션 STATELESS 처리
            .sessionManagement()
            .sessionCreationPolicy(SessionCreationPolicy.STATELESS)

            // 비활성화 필터와 커스텀 필터를 추가
            .and()
            .csrf().disable()
            .formLogin().disable()
            .httpBasic(Customizer.withDefaults())
            .addFilter(corsFilter())
            .addFilter(usernamePasswordAuthenticationFilter())
            .addFilterBefore(customJwtAuthorizationFilter, BasicAuthenticationFilter::class.java)
            .addFilterBefore(jwtAuthorizationExceptionFilter, CustomJwtAuthorizationFilter::class.java)
            .authorizeRequests()
            .antMatchers("/graphql").permitAll()
            .antMatchers("/graphiql").permitAll()
            .anyRequest().permitAll()

            // 인증,인가 exception handling 시 커스텀 파일로 처리
            .and()
            .exceptionHandling()
            .authenticationEntryPoint(customAuthenticationEntryPoint)
            .accessDeniedHandler(customAccessDeniedHandler)

            // 로그아웃 시 로그인 페이지로 이동
            .and()
            .logout()
            .logoutSuccessUrl("/api/v1/login") // 로그아웃에 대해서 성공하면 "/"로 이동

        return http.build()
    }

    /***
     * 로그인 시 authentication 필터 적용
     */
    fun usernamePasswordAuthenticationFilter(): UsernamePasswordAuthenticationFilter? {
        return CustomUsernamePasswordAuthenticationFilter(
            authenticationManager(authenticationConfiguration),
            jwtProviderService
        ).apply { setFilterProcessesUrl("/api/v1/login") }
    }

    @Bean
    fun authenticationManager(authenticationConfiguration: AuthenticationConfiguration): AuthenticationManager {
        return authenticationConfiguration.authenticationManager
    }

    @Bean
    fun authProvider() : DaoAuthenticationProvider {
        return DaoAuthenticationProvider()
            .also { it.setPasswordEncoder(passwordEncoder) }
            .also { it.setUserDetailsService(principalUserDetailsService) }
    }
}