package academy.devdojo.core.model;

import lombok.*;

import javax.persistence.*;
import javax.validation.constraints.NotNull;

import static javax.persistence.GenerationType.IDENTITY;

@Entity
@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
@ToString
@EqualsAndHashCode(onlyExplicitlyIncluded = true)
public class ApplicationUser implements AbstractEntity {

    @Id
    @GeneratedValue(strategy = IDENTITY)
    @EqualsAndHashCode.Include
    private Long id;
    @NotNull(message = "The field 'username' is mandatory")
    @Column(nullable = false)
    private String username;
    @ToString.Exclude
    @NotNull(message = "The field 'password' is mandatory")
    @Column(nullable = false)
    private String password;
    @NotNull(message = "The field 'role' is mandatory")
    @Column(nullable = false)
    private String role = "USER";

    public ApplicationUser(@NotNull ApplicationUser applicationUser) {
        this.id = applicationUser.getId();
        this.username = applicationUser.getUsername();
        this.password = applicationUser.getPassword();
        this.role = applicationUser.getRole();
    }

    @Override
    public Long getId() {
        return id;
    }
}
