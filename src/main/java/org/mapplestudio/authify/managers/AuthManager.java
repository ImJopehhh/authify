package org.mapplestudio.authify.managers;

import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

public class AuthManager {
    private final Map<UUID, AuthSession> sessions = new ConcurrentHashMap<>();
    // Temporary map for login process before UUID is finalized or for connection handling
    private final Map<String, AuthSession> pendingSessions = new ConcurrentHashMap<>();

    public AuthSession createSession(UUID uuid) {
        AuthSession session = new AuthSession(uuid);
        sessions.put(uuid, session);
        return session;
    }

    public AuthSession getSession(UUID uuid) {
        return sessions.get(uuid);
    }

    public void removeSession(UUID uuid) {
        sessions.remove(uuid);
    }
    
    public boolean isAuthenticated(UUID uuid) {
        AuthSession session = sessions.get(uuid);
        return session != null && session.isLoggedIn();
    }
}
