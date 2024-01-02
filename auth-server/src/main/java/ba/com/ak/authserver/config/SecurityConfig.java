package ba.com.ak.authserver.config;

import static org.springframework.security.config.Customizer.withDefaults;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.UUID;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

import ba.com.ak.authserver.repository.UserRepository;
import ba.com.ak.authserver.service.JdbcUserDetailsService;

@Configuration
public class SecurityConfig {

	@Bean
	@Order(1)
	SecurityFilterChain asSecurityFilterChain(HttpSecurity http) throws Exception {
		OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
		return http.getConfigurer(OAuth2AuthorizationServerConfigurer.class).oidc(withDefaults()).and()
				.exceptionHandling(e -> e.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login")))
				.oauth2ResourceServer((oauth2) -> oauth2.jwt(Customizer.withDefaults())).build();
	}

	/**
	 * User information container class, used to obtain user information during Form
	 * authentication.
	 *
	 * @param userRepository
	 * @return
	 */
	@Bean
	UserDetailsService userDetailsService(UserRepository userRepository) {
		return new JdbcUserDetailsService(userRepository);
	}

	@Bean
	@Order(2)
	SecurityFilterChain appSecurityFilterChain(HttpSecurity http) throws Exception {
		return http.formLogin(withDefaults()).authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated())
				.build();

	}

	/*
	 * @Bean UserDetailsService userDetailsService() { var user1 =
	 * User.withUsername("user") .password("password") .roles("USER")
	 * .authorities("read") .build(); return new InMemoryUserDetailsManager(user1);
	 * }
	 */

	@Bean
	PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder(12);
		// return NoOpPasswordEncoder.getInstance();
	}

	@Bean
	RegisteredClientRepository registeredClientRepository() {
		RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString()).clientId("client")
				.clientSecret("$2a$12$EHJ/hFl9Cje4gRJJVtEFHeNFiXuY.Zlyo.KjuNNwsZtwnFlLFTw1W").scope("read")
				.scope(OidcScopes.OPENID).scope(OidcScopes.PROFILE)
				.redirectUri("http://localhost:8080/login/oauth2/code/gateway")
				.postLogoutRedirectUri("http://localhost:8080")
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
				.clientSettings(
						ClientSettings.builder().requireAuthorizationConsent(false).requireProofKey(false).build())
				.tokenSettings(TokenSettings.builder().accessTokenFormat(OAuth2TokenFormat.SELF_CONTAINED)
						.idTokenSignatureAlgorithm(SignatureAlgorithm.RS256)
						.accessTokenTimeToLive(Duration.ofSeconds(30 * 60))
						.refreshTokenTimeToLive(Duration.ofSeconds(60 * 60)).reuseRefreshTokens(true).build())
				.build();

		return new InMemoryRegisteredClientRepository(registeredClient);
	}

	@Bean
	AuthorizationServerSettings authorizationServerSettings() {
		return AuthorizationServerSettings.builder().build();
	}

	@Bean
	JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
		return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
	}

	@Bean
	JWKSource<SecurityContext> jwkSource() {
		RSAKey rsaKey = generateRsa();
		JWKSet jwkSet = new JWKSet(rsaKey);
		return (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
	}

	public static RSAKey generateRsa() {
		KeyPair keyPair = generateRsaKey();
		RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
		RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
		return new RSAKey.Builder(publicKey).privateKey(privateKey).keyID(UUID.randomUUID().toString()).build();
	}

	static KeyPair generateRsaKey() {
		KeyPair keyPair;
		try {
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
			keyPairGenerator.initialize(2048);
			keyPair = keyPairGenerator.generateKeyPair();
		} catch (Exception ex) {
			throw new IllegalStateException(ex);
		}
		return keyPair;
	}
}
