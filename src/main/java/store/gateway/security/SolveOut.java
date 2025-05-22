package store.gateway.security;

import lombok.Builder;
import lombok.experimental.Accessors;

@Builder @Accessors(fluent = true)
public record SolveOut(
    String idAccount
) {
    
}
