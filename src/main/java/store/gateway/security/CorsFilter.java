package store.gateway.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsWebFilter;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;

@Configuration
public class CorsFilter {

    @Bean
    public CorsWebFilter corsWebFilter() {

        CorsConfiguration corsConfig = new CorsConfiguration();
        corsConfig.setAllowCredentials(false);
        corsConfig.addAllowedHeader("*");
        corsConfig.addAllowedMethod("*");
        corsConfig.addAllowedOrigin("*");

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", corsConfig);

        return new CorsWebFilter(source);
    }
    
}
