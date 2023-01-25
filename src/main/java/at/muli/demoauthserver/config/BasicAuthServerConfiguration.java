package at.muli.demoauthserver.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.Collections;
import java.util.UUID;

@Configuration
public class BasicAuthServerConfiguration {

    /**
     * Defines the authentication entry point at "/login".
     * <p>
     * Uses the default security from {@link OAuth2AuthorizationServerConfiguration}. Should be customized.
     * </p>
     *
     * @param http the {@link HttpSecurity} to customize on.
     * @return the updated {@link SecurityFilterChain}.
     * @throws Exception when the configuration cannot be applied.
     */
    @Bean
    @Order(1)
    public SecurityFilterChain onSecurityFilterChain(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
        return http
                .cors().configurationSource(corsConfigurationSource()).and()
                // TODO probably we need another check here as well.
                .exceptionHandling(exceptions -> exceptions.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login")))
                .build();
    }

    /**
     * Creates the Spring default login mask if not already logged in.
     *
     * @param http the {@link HttpSecurity} to customize on.
     * @return the updated {@link SecurityFilterChain}.
     * @throws Exception when the configuration cannot be applied.
     */
    @Bean
    @Order(2)
    public SecurityFilterChain appSecurityFilterChain(HttpSecurity http) throws Exception {
        return http
                .authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated())
                // TODO here we need to implement another check for a valid user.
                .formLogin(Customizer.withDefaults())
                .build();
    }

    /**
     * Allows cors requests from <a href="https://oidcdebugger.com">OIDC Debugger</a> which retrieves the token via the browser.
     */
    private CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration corsConfiguration = new CorsConfiguration();
        corsConfiguration.setAllowedOrigins(Arrays.asList("https://oidcdebugger.com", "http://localhost:8080"));
        corsConfiguration.setAllowedMethods(Collections.singletonList(HttpMethod.POST.name()));
        corsConfiguration.setAllowedHeaders(Collections.singletonList("*"));
        UrlBasedCorsConfigurationSource corsConfigurationSource = new UrlBasedCorsConfigurationSource();
        corsConfigurationSource.registerCorsConfiguration("/oauth2/token", corsConfiguration);
        return corsConfigurationSource;
    }

    /**
     * Standard hardcoded user configuration.
     * <p>
     * Really shouldn't be used outside of demo purposes. Just here for simplicity of design.
     * </p>
     *
     * @return the service with the default user details.
     */
    @Bean
    public UserDetailsService userDetailsService() {
        return new InMemoryUserDetailsManager(
                User.withDefaultPasswordEncoder()
                        .username("user")
                        .password("password")
                        .roles("USER")
                        .build());
    }

    /**
     * Defines which clients are allowed.
     * <p>
     * This could be additional applications (resource servers) which request access.
     * </p>
     * <p>
     * For demo purposes this is handled in-memory with just one client: "my-client".
     * </p>
     *
     * @return the single client static repository.
     */
    @Bean
    public RegisteredClientRepository registeredClientRepository() {
        return new InMemoryRegisteredClientRepository(
                RegisteredClient.withId(UUID.randomUUID().toString())
                        // this is the requested client id in the parameter "client_id"
                        .clientId("my-client")
                        // this client secret seems not be in use
                        .clientSecret("{noop}secret")
//                        .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
//                        .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_JWT)
//                        .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
//                        .clientAuthenticationMethod(ClientAuthenticationMethod.PRIVATE_KEY_JWT)
                        // currently we do not want any clientAuthenticationMethod since the token should be provided
                        // only via PKCE exchange.
                        .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                        .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
//                        .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                        // allowing localhost and the oidc debugger to be valid redirection targets
                        .redirectUri("http://127.0.0.1:8080/authorized")
                        .redirectUri("https://oidcdebugger.com/debug")
//                        .scope(OidcScopes.OPENID)
//                        .scope(OidcScopes.PROFILE)
                        .scope("message.read") // custom scope which we will use for the demo
                        .clientSettings(ClientSettings.builder()
                                .requireAuthorizationConsent(true) // this requires the user to allow the access to this scope. no additional step will be displayed if commented or false.
                                .build())
                        .build());
    }

    /**
     * Provider of the public/private key pair for the token.
     * <p>
     * Probably the key will be provided per deployment configuration in a real world example.
     * </p>
     *
     * @return the source for the jwt key.
     * @throws Exception when the key generation is unsuccessful.
     */
    @Bean
    public JWKSource<SecurityContext> jwkSource() throws Exception {
        KeyPair keyPair = generateRsaKey();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        RSAKey rsaKey = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString())
                .build();
        return new ImmutableJWKSet<>(new JWKSet(rsaKey));
    }

    /**
     * Default {@link AuthorizationServerSettings} for demo purposes initializes with default URLs.
     *
     * @return the built settings.
     */
    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder().build();
    }

    private KeyPair generateRsaKey() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        return keyPairGenerator.generateKeyPair();
    }
}
