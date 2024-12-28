package com.lean.Security.user;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static com.lean.Security.user.Permission.*;

@RequiredArgsConstructor
public enum Role {
    USER(Collections.EMPTY_SET),
    ADMIN(Set.of(
            ADMIN_READ,
            ADMIN_DELETE,
            ADMIN_UPDATE,
            ADMIN_CREATE,
            MANAGER_DELETE,
            MANAGER_CREATE,
            MANAGER_UPDATE,
            MANAGER_READ
    )),
    MANAGER(Set.of(
            MANAGER_DELETE,
            MANAGER_CREATE,
            MANAGER_UPDATE,
            MANAGER_READ
    ));

    @Getter
    private final Set<Permission> permissions;

    public List<SimpleGrantedAuthority> getUserAuthority(){
        var authority = getPermissions().stream()
                .map(permission -> new SimpleGrantedAuthority(permission.name()))
                .toList();
        authority.add(new SimpleGrantedAuthority("ROLE_"+this.name()));
        return authority;
    }
}
