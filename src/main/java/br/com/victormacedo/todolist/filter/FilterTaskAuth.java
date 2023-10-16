package br.com.victormacedo.todolist.filter;

import at.favre.lib.crypto.bcrypt.BCrypt;
import br.com.victormacedo.todolist.user.IUserRepository;
import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Base64;

@Component
public class FilterTaskAuth extends OncePerRequestFilter {
    @Autowired
    private IUserRepository userRepository;
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        var servletPath = request.getServletPath();
        if(servletPath.startsWith("/tasks/")){
            //Pegar a autenticação (usuario e senha)
            var authorization = request.getHeader("Authorization");

            var authDecoded = authorization.substring("Basic".length()).trim();

            byte[] authDecode = Base64.getDecoder().decode(authDecoded);

            var authString = new String(authDecode);

            System.out.println("Authorization");
            System.out.println(authString);

            String[] credential = authString.split(":");
            String username = credential[0];
            String password = credential[1];
            System.out.println(username + password);

            //Validar usuário
            var user = this.userRepository.findByUsername(username);
            if(user == null){
                response.sendError(401, "Usuário sem autorização");
            } else{
                // Validar senha
                var passwordVerify = BCrypt.verifyer().verify(password.toCharArray(), user.getPassword());
                if(passwordVerify.verified){
                    request.setAttribute("idUser", user.getId());
                    filterChain.doFilter(request, response);
                } else {
                    response.sendError(401, "Usuário sem autorização");
                }
            }
        } else {
            filterChain.doFilter(request, response);
        }
    }
}
