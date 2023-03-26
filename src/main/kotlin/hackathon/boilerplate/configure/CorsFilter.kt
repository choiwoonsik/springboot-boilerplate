package hackathon.boilerplate.configure

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.web.cors.CorsConfiguration
import org.springframework.web.cors.UrlBasedCorsConfigurationSource
import org.springframework.web.filter.CorsFilter

@Configuration
class CorsConfig {
    @Bean
    fun corsFilter(): CorsFilter {
        val source = UrlBasedCorsConfigurationSource()
        val configuration = CorsConfiguration()
        configuration.addAllowedMethod("*")
        configuration.addAllowedHeader("*")
        configuration.addAllowedOrigin("*")
        configuration.allowCredentials = true
        source.registerCorsConfiguration("/**", configuration)
        return CorsFilter(source)
    }
}