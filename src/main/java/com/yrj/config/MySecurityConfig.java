package com.yrj.config;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@EnableWebSecurity
public class MySecurityConfig extends WebSecurityConfigurerAdapter {
    @Bean
    public PasswordEncoder passwordEncoder() {
        // return PasswordEncoderFactories.createDelegatingPasswordEncoder();
        return new BCryptPasswordEncoder();
    }
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        //super.configure(auth);
        auth.inMemoryAuthentication().passwordEncoder(passwordEncoder())
                .withUser("user1").password(passwordEncoder().encode("123")).roles("vip1","vip2")
                .and()
                .withUser("user2").password(passwordEncoder().encode("123")).roles("vip1","vip3")
                .and()
                .withUser("user3").password(passwordEncoder().encode("123")).roles("vip2","vip3");

    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        //super.configure(http);
        http.authorizeRequests().antMatchers("/").permitAll()
                .antMatchers("/level1/**").hasRole("vip1")
                .antMatchers("/level2/**").hasRole("vip2")
                .antMatchers("/level3/**").hasRole("vip3");

        http.formLogin().usernameParameter("user").passwordParameter("pwd").loginPage("/userlogin");

        http.logout().logoutSuccessUrl("/");

        http.rememberMe().rememberMeParameter("remember");
    }

//    @Bean
//    public SpringResourceTemplateResolver templateResolver(){
//        SpringResourceTemplateResolver templateResolver = new SpringResourceTemplateResolver();
//        //配置模板
//        templateResolver.setPrefix("classpath:/templates/");
//        templateResolver.setSuffix(".html");
//        // 使用HTML的模式，也就是支持HTML5的方式，使用data-th-*的H5写法来写thymeleaf的标签语法
//        templateResolver.setTemplateMode(TemplateMode.HTML);
//        // 之前在application.properties中看到的缓存配置
//        templateResolver.setCacheable(true);
//
//        return templateResolver;
//    }
//
//    @Bean
//    public SpringTemplateEngine templateEngine() {
//        //模板引擎增加SpringSecurityDialect，让模板能用到sec前缀，获取spring security的内容
//        SpringTemplateEngine engine = new SpringTemplateEngine();
//        SpringSecurityDialect securityDialect = new SpringSecurityDialect();
//        Set<IDialect> dialects = new HashSet<>();
//        dialects.add(securityDialect);
//        engine.setAdditionalDialects(dialects);
//
//        engine.setTemplateResolver(templateResolver());
//        //允许在内容中使用spring EL表达式
//        engine.setEnableSpringELCompiler(true);
//
//        return engine;
//    }
//
//    //声明ViewResolver
//    @Bean
//    public ThymeleafViewResolver viewResolver(){
//        ThymeleafViewResolver viewResolver = new ThymeleafViewResolver();
//        viewResolver.setTemplateEngine(templateEngine());
//        return viewResolver;
//    }
}
