package academy.devdojo.youtube.auth.security.user;

import academy.devdojo.core.model.ApplicationUser;
import academy.devdojo.core.repository.ApplicationUserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import javax.validation.constraints.NotNull;
import java.util.Collection;
import java.util.Objects;

import static org.springframework.security.core.authority.AuthorityUtils.commaSeparatedStringToAuthorityList;

@RequiredArgsConstructor(onConstructor = @__(@Autowired))
@Service
@Slf4j
public class UserDetailsServiceImpl implements UserDetailsService {

    private final ApplicationUserRepository repository;

    @Override
    public UserDetails loadUserByUsername(String username) {
        log.info("Searching in the DB the user by username '{}'", username);
        final ApplicationUser applicationUser = repository.findByUsername(username);
        if(Objects.isNull(applicationUser)) {
            throw new UsernameNotFoundException(String.format("Application user '%s' not found", username));
        }
        log.info("Application user found '{}'", applicationUser);
        return new CustomUserDetails(applicationUser);
    }

    public static final class CustomUserDetails extends ApplicationUser implements UserDetails {

        CustomUserDetails(@NotNull ApplicationUser applicationUser) {
            super(applicationUser);
        }

        @Override
        public Collection<? extends GrantedAuthority> getAuthorities() {
            return commaSeparatedStringToAuthorityList("ROLE_" + this.getRole());
        }

        @Override
        public boolean isAccountNonExpired() {
            return true;
        }

        @Override
        public boolean isAccountNonLocked() {
            return true;
        }

        @Override
        public boolean isCredentialsNonExpired() {
            return true;
        }

        @Override
        public boolean isEnabled() {
            return true;
        }
    }

}
