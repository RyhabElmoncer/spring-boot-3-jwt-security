package com.RyhabExemple.security.user;

import com.RyhabExemple.security.token.Token;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;
import org.springframework.data.mongodb.core.mapping.DBRef;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;


@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder

@Document(collection = "users")
public class User implements UserDetails {


  @Id
  private String id;
  private String firstname;
  private String lastname;
  private String email;  
  private String password;
  private Role role;

  /**
   * Annotation Spring Data MongoDB qui spécifie une référence à une autre collection. Ici, la liste des tokens associés à l'utilisateur.
   */
  @DBRef
  private List<Token> tokens;

  /**
   * Retourne les autorisations (permissions) accordées à l'utilisateur, basées sur son rôle.
   * @return Collection des autorités (permissions) accordées à l'utilisateur.
   */
  @Override
  public Collection<? extends GrantedAuthority> getAuthorities() {
    return role.getAuthorities();
  }

  /**
   * Retourne le mot de passe de l'utilisateur.
   * @return Mot de passe de l'utilisateur.
   */
  @Override
  public String getPassword() {
    return password;
  }

  /**
   * Retourne le nom d'utilisateur, ici l'adresse email de l'utilisateur.
   * @return Adresse email de l'utilisateur.
   */
  @Override
  public String getUsername() {
    return email;
  }

  /**
   * Indique si le compte de l'utilisateur a expiré.
   * Ici, toujours vrai (non expiré).
   * @return Toujours true.
   */
  @Override
  public boolean isAccountNonExpired() {
    return true;
  }

  /**
   * Indique si le compte de l'utilisateur est verrouillé.
   * Ici, toujours vrai (non verrouillé).
   * @return Toujours true.
   */
  @Override
  public boolean isAccountNonLocked() {
    return true;
  }

  /**
   * Indique si les informations d'identification (mot de passe) de l'utilisateur ont expiré.
   * Ici, toujours vrai (non expiré).
   * @return Toujours true.
   */
  @Override
  public boolean isCredentialsNonExpired() {
    return true;
  }

  /**
   * Indique si l'utilisateur est activé.
   * Ici, toujours vrai (activé).
   * @return Toujours true.
   */
  @Override
  public boolean isEnabled() {
    return true;
  }

  /**
   * Retourne l'identifiant de l'utilisateur.
   * @return Identifiant de l'utilisateur.
   */
  public String getId() {
    return id;
  }
}
