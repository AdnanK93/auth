package ba.com.ak.authserver.service;

import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.util.CollectionUtils;
import org.springframework.util.ObjectUtils;

import ba.com.ak.authserver.entity.Role;
import ba.com.ak.authserver.repository.UserRepository;
import lombok.RequiredArgsConstructor;

/**
 * User service, used to obtain user information during Form authentication
 *
 * @author: ReLive
 * @date: 2022/8/4 19:27
 */
@RequiredArgsConstructor
public class JdbcUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
    	ba.com.ak.authserver.entity.User user = userRepository.findUserByUsername(username);
        if (ObjectUtils.isEmpty(user)) {
            throw new UsernameNotFoundException("user is not found");
        }
        if (CollectionUtils.isEmpty(user.getRoleList())) {
            throw new UsernameNotFoundException("role is not found");
        }
        Set<SimpleGrantedAuthority> authorities = user.getRoleList().stream().map(Role::getRoleCode)
                .map(SimpleGrantedAuthority::new).collect(Collectors.toSet());
        return new User(user.getUsername(), user.getPassword(), authorities);
    }
    
}