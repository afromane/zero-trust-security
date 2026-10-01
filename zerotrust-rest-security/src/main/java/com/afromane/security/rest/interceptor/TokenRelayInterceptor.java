package com.afromane.security.rest.interceptor;

import org.springframework.http.HttpHeaders;
import org.springframework.http.client.ClientHttpRequestExecution;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import java.io.IOException;

/**
 * Intercepteur de requêtes HTTP clientes propageant automatiquement l'identité de l'utilisateur (Token Relay).
 * <p>
 * Lorsqu'un microservice en appelle un autre via {@code RestClient} ou {@code RestTemplate}, cet intercepteur
 * extrait le jeton JWT du contexte de sécurité courant ({@link SecurityContextHolder}) et l'injecte
 * dans l'en-tête {@code Authorization: Bearer <token>} de la requête sortante.
 * </p>
 * <p>
 * Cette approche évite d'écrire du code de plomberie pour chaque appel inter-services tout en maintenant
 * la traçabilité de l'utilisateur final à travers toute la chaîne de microservices.
 * </p>
 *
 * @author afromane
 * @version 1.0.0
 */
public class TokenRelayInterceptor implements ClientHttpRequestInterceptor {

    /**
     * Intercepte la requête sortante et attache le token JWT courant si présent.
     *
     * @param request   requête HTTP cliente sortante (qualifiée explicitement pour éviter les conflits JDK)
     * @param body      corps binaire de la requête
     * @param execution chaîne d'exécution de la requête
     * @return réponse HTTP renvoyée par le service cible
     * @throws IOException en cas d'erreur de communication réseau
     */
    @Override
    public ClientHttpResponse intercept(
            org.springframework.http.HttpRequest request,
            byte[] body,
            ClientHttpRequestExecution execution) throws IOException {

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication instanceof JwtAuthenticationToken jwtAuth) {
            String tokenValue = jwtAuth.getToken().getTokenValue();
            if (request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION) == null) {
                request.getHeaders().setBearerAuth(tokenValue);
            }
        }

        return execution.execute(request, body);
    }
}
