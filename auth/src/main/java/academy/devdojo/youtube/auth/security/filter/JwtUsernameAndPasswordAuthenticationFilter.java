package academy.devdojo.youtube.auth.security.filter;

import academy.devdojo.core.model.ApplicationUser;
import academy.devdojo.core.property.JwtConfiguration;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.DirectEncrypter;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;
import java.util.Objects;
import java.util.UUID;

import static java.util.Collections.emptyList;
import static java.util.stream.Collectors.toList;

@RequiredArgsConstructor(onConstructor = @__(@Autowired))
@Slf4j
public class JwtUsernameAndPasswordAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;
    private final JwtConfiguration jwtConfiguration;

    @Override
    @SneakyThrows
    public Authentication attemptAuthentication(HttpServletRequest req, HttpServletResponse resp) {
        log.info("Attempting authentication . . . ");

        ApplicationUser applicationUser = new ObjectMapper().readValue(req.getInputStream(), ApplicationUser.class);

        if (Objects.isNull(applicationUser)) {
            throw new UsernameNotFoundException("Unable to retrieve the username or password");
        }
        log.info("Creating the authentication object for the user '{}' and calling UserDetailServiceImpl loadByUsername", applicationUser.getUsername());

        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(applicationUser.getUsername(), applicationUser.getPassword(), emptyList());
        usernamePasswordAuthenticationToken.setDetails(applicationUser);

        return authenticationManager.authenticate(usernamePasswordAuthenticationToken);
    }

    @Override
    @SneakyThrows
    protected void successfulAuthentication(HttpServletRequest req, HttpServletResponse resp, FilterChain chain, Authentication auth) throws IOException, ServletException {
        log.info("Authentication was successful for the user '{}', generating JWE token", auth.getName());
        SignedJWT signedJWT = createSignedJWT(auth);
        String encryptToken = encryptToken(signedJWT);
        log.info("Token generated successfully, adding it to the response header");
        resp.addHeader("Access-Control-Expose-Headers", "XSRF-TOKEN, " + jwtConfiguration.getHeader().getName());
        resp.addHeader(jwtConfiguration.getHeader().getName(), jwtConfiguration.getHeader().getPrefix() + encryptToken);
    }

    @SneakyThrows
    private SignedJWT createSignedJWT(Authentication auth) {
        log.info("Starting to create the signed JWT");
        ApplicationUser applicationUser = (ApplicationUser) auth.getPrincipal();
        JWTClaimsSet jwtClaimSet = createJWTClaimSet(auth, applicationUser);
        KeyPair rsaKeys = generateKeyPar();
        log.info("Building JWK from RSA keys");
        JWK jwk = new RSAKey.Builder((RSAPublicKey) rsaKeys.getPublic()).keyID(UUID.randomUUID().toString()).build();
        SignedJWT signedJWT = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256)
                .jwk(jwk)
                .type(JOSEObjectType.JWT).build(), jwtClaimSet);
        log.info("Signing the token with the private RSA Key");
        RSASSASigner signer = new RSASSASigner(rsaKeys.getPrivate());
        signedJWT.sign(signer);

        log.info("Serialized token {}", signedJWT.serialize());
        return signedJWT;
    }

    private JWTClaimsSet createJWTClaimSet(Authentication auth, ApplicationUser applicationUser) {
        log.info("Creating the JWTClaimSet object for '{}'", applicationUser);
        return new JWTClaimsSet.Builder()
                .subject(applicationUser.getUsername())
                .claim("authorities", auth.getAuthorities()
                .stream()
                .map(GrantedAuthority::getAuthority)
                .collect(toList()))
                .issuer("http://academy.devdojo")
                .issueTime(new Date())
                .expirationTime(new Date(System.currentTimeMillis() + (jwtConfiguration.getExpiration() * 1000)))
                .build();
    }

    @SneakyThrows
    private KeyPair generateKeyPar() {
        log.info("Generate RSA 2048 bits keys");
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }

    private String encryptToken(SignedJWT signedJWT) throws JOSEException {
        log.info("Starting the encryptionToken method");
        DirectEncrypter directEncrypter = new DirectEncrypter(jwtConfiguration.getPrivateKey().getBytes());
        JWEObject jweObject = new JWEObject(new JWEHeader.Builder(JWEAlgorithm.DIR, EncryptionMethod.A128CBC_HS256)
                .contentType("JWE")
                .build(), new Payload(signedJWT));
        log.info("Encrypting token with system's private key");
        jweObject.encrypt(directEncrypter);
        log.info("Token encrypted");
        return jweObject.serialize();
    }
}
