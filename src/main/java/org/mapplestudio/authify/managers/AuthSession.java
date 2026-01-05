package org.mapplestudio.authify.managers;

import java.util.UUID;

public class AuthSession {
    private final UUID uuid;
    private boolean isLoggedIn;
    private boolean isPremium;
    private byte[] verifyToken;

    public AuthSession(UUID uuid) {
        this.uuid = uuid;
        this.isLoggedIn = false;
        this.isPremium = false;
    }

    public UUID getUuid() {
        return uuid;
    }

    public boolean isLoggedIn() {
        return isLoggedIn;
    }

    public void setLoggedIn(boolean loggedIn) {
        isLoggedIn = loggedIn;
    }

    public boolean isPremium() {
        return isPremium;
    }

    public void setPremium(boolean premium) {
        isPremium = premium;
    }

    public byte[] getVerifyToken() {
        return verifyToken;
    }

    public void setVerifyToken(byte[] verifyToken) {
        this.verifyToken = verifyToken;
    }
}
