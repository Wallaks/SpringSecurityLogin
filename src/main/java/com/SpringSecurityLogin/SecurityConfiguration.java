package com.SpringSecurityLogin;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration // dizer que é uma classe de configuração
@EnableWebSecurity // dizer que é oara configuração de web
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {
	@Bean
	public static BCryptPasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.authorizeRequests().antMatchers("/").access("hasAnyAuthority('USERS', 'ADMIN')")//
				.antMatchers("/admin").access("hasAnyAuthority('ADMIN')")//
				.anyRequest().authenticated().and().formLogin().loginPage("/login").permitAll()//
				.and()//
				.logout().logoutRequestMatcher(new AntPathRequestMatcher("/logout"))//
				.logoutSuccessUrl("/login").permitAll();//
	}

	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.inMemoryAuthentication().withUser("wallaks").password(passwordEncoder().encode("wallaks2023"))//
				.authorities("ADMIN")//
				.and()//
				.withUser("user").password(passwordEncoder().encode("password"))//
				.authorities("USER");//
	}
}
// O método configure(HttpSecurity http) é usado para configurar as regras de
// segurança do aplicativo em relação às solicitações HTTP que chegam ao servidor.
// Ele faz parte da classe WebSecurityConfigurerAdapter do Spring Security e é
// usado para definir como o Spring Security protegerá o aplicativo.
// No código fornecido, o método configure(HttpSecurity http) especifica que
// todas as solicitações de HTTP devem ser autenticadas antes de serem permitidas.
// Isso é feito por meio do método authorizeRequests() que define as regras de autorização.
// A expressão .anyRequest().authenticated() significa que qualquer solicitação que não
// seja correspondida por outra regra deve ser autenticada antes de ser permitida.
// Ou seja, para acessar qualquer URL, o usuário deve ser autenticado.
// O método formLogin() é usado para especificar que o formulário de login
// deve ser exibido quando um usuário não autenticado tenta acessar uma URL
// protegida. Ele define as opções de configuração para a página de login,
// como a URL da página de login e os campos do formulário de login.

// O método configure(AuthenticationManagerBuilder auth) é usado para configurar
// o mecanismo de autenticação no Spring Security. Ele faz parte da classe
// WebSecurityConfigurerAdapter do Spring Security e é usado para definir como
// o Spring Security irá autenticar os usuários.
// No código fornecido, o método configure(AuthenticationManagerBuilder auth)
// usa um AuthenticationProvider em memória para autenticar usuários.
// Ele adiciona um único usuário com o nome de usuário "user", a senha
// "password" e a autoridade "USER" (ou seja, um usuário comum) usando
// o método inMemoryAuthentication().
// O método passwordEncoder().encode("password") é usado para criptografar
// a senha "password" antes de armazená-la na memória. Isso é importante
// para garantir que a senha do usuário não seja armazenada em texto simples
// no código ou no banco de dados. O método passwordEncoder() retorna um
// objeto PasswordEncoder que é usado para criptografar a senha.