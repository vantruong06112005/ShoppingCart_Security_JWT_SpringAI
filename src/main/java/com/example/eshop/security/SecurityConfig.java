
package com.example.eshop.security;

import lombok.RequiredArgsConstructor;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity // Bật @PreAuthorize
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtService jwtService;
    private final CustomUserDetailsService userDetailsService;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
     * Spring Boot tự cấu hình DaoAuthenticationProvider
     * từ UserDetailsService và PasswordEncoder.
     */
    @Bean
    public AuthenticationManager authenticationManager(
            AuthenticationConfiguration config
    ) throws Exception {
        return config.getAuthenticationManager();
    }

    private JwtAuthenticationFilter jwtFilter() {
        return new JwtAuthenticationFilter(
                jwtService,
                userDetailsService
        );
    }

    // ================= CHAIN 1: REST API (/api/**) =================

    @Bean
    @Order(1)
    public SecurityFilterChain apiFilterChain(
            HttpSecurity http
    ) throws Exception {
        http
                .securityMatcher("/api/**")
                .csrf(AbstractHttpConfigurer::disable)
                // API sử dụng header Bearer, không dùng cookie.
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )
                // Người chưa đăng nhập mang quyền ROLE_GUEST.
                .anonymous(anonymous -> anonymous
                        .authorities("ROLE_GUEST")
                )
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/api/auth/**").permitAll()
                        .requestMatchers(
                                HttpMethod.GET,
                                "/api/products/**"
                        ).permitAll()
                        .requestMatchers("/api/orders/**")
                        .hasRole("CUSTOMER")
                        .anyRequest().hasRole("SELLER")
                )
                .exceptionHandling(exception -> exception
                        .authenticationEntryPoint(
                                new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED)
                        )
                ) // Trả về 401 khi chưa xác thực.
                .addFilterBefore(
                        jwtFilter(),
                        UsernamePasswordAuthenticationFilter.class
                );

        return http.build();
    }

    // ================= CHAIN 2: WEB (Thymeleaf) =================

    @Bean
    @Order(2)
    public SecurityFilterChain webFilterChain(
            HttpSecurity http
    ) throws Exception {
        http
                // Không lưu thông tin đăng nhập vào session.
                // JWT nằm trong cookie.
                // Ứng dụng vẫn dùng HttpSession cho giỏ hàng
                // và CSRF token.
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )
                // Người chưa đăng nhập mang quyền ROLE_GUEST.
                .anonymous(anonymous -> anonymous
                        .authorities("ROLE_GUEST")
                )
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(
                                "/css/**",
                                "/js/**",
                                "/images/**",
                                "/favicon.ico",
                                "/error",
                                "/403"
                        ).permitAll()

                        .requestMatchers(
                                "/",
                                "/products",
                                "/products/**",
                                "/login"
                        ).permitAll()

                        .requestMatchers("/register")
                        .hasRole("GUEST")

                        .requestMatchers("/admin/**")
                        .hasRole("SELLER")

                        .requestMatchers(
                                "/cart/**",
                                "/checkout/**",
                                "/orders/**"
                        ).hasRole("CUSTOMER")

                        .anyRequest().authenticated()
                )
                .exceptionHandling(exception -> exception
                        .authenticationEntryPoint(
                                new LoginUrlAuthenticationEntryPoint("/login")
                        ) // Chưa đăng nhập thì chuyển đến /login.
                        .accessDeniedPage("/403") // Thiếu quyền thì chuyển đến /403.
                )
                .logout(logout -> logout
                        .logoutUrl("/logout") // POST /logout, có CSRF.
                        .deleteCookies(
                                JwtService.COOKIE_NAME,
                                "JSESSIONID"
                        )
                        .invalidateHttpSession(true) // Xóa luôn giỏ hàng trong session.
                        .logoutSuccessUrl("/?logout")
                )
                .addFilterBefore(
                        jwtFilter(),
                        UsernamePasswordAuthenticationFilter.class
                );

        // CSRF được bật mặc định.
        // th:action của Thymeleaf tự chèn input _csrf.

        return http.build();
    }
}
