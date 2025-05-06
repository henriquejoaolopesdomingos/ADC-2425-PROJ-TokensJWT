package pt.unl.fct.di.apdc.firstwebapp.authentication;

import pt.unl.fct.di.apdc.firstwebapp.util.JWTConfig;
import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.SignatureVerificationException;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.auth0.jwt.interfaces.DecodedJWT;

import java.util.Date;

public class JWTToken {

    public static String createJWT(String username, String role) {
        Algorithm algorithm = JWTConfig.getJWTAlgorithm();
        long now = System.currentTimeMillis();
        long expires = now + JWTConfig.EXPIRATION_TIME;

        return JWT.create()
                .withSubject(username)
                .withClaim("role", role)
                .withIssuedAt(new Date(now))
                .withExpiresAt(new Date(expires))
                .sign(algorithm);
    }

    public static boolean validateJWT(String token) {
        try {
            Algorithm algorithm = JWTConfig.getJWTAlgorithm();
            JWTVerifier verifier = JWT.require(algorithm).build();
            DecodedJWT decoded = verifier.verify(token);

            // Manually check expiration
            Date expiresAt = decoded.getExpiresAt();
            return expiresAt == null || expiresAt.after(new Date());

        } catch (SignatureVerificationException e) {
            System.out.println("Invalid signature");
            return false;
        } catch (TokenExpiredException e) {
            System.out.println("Token expired");
            return false;
        } catch (Exception e) {
            System.out.println("Invalid token: " + e.getMessage());
            return false;
        }
    }

    public static DecodedJWT extractJWT(String token) {
        try {
            Algorithm algorithm = JWTConfig.getJWTAlgorithm();
            JWTVerifier verifier = JWT.require(algorithm).build();
            DecodedJWT decoded = verifier.verify(token);

            return decoded;
        } catch (Exception e) {
            return null;
        }
    }
}