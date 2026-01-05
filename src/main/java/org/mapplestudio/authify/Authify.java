package org.mapplestudio.authify;

import com.comphenix.protocol.ProtocolLibrary;
import com.comphenix.protocol.ProtocolManager;
import org.bukkit.Bukkit;
import org.bukkit.plugin.java.JavaPlugin;
import org.mapplestudio.authify.commands.LoginCommand;
import org.mapplestudio.authify.commands.RegisterCommand;
import org.mapplestudio.authify.database.DatabaseManager;
import org.mapplestudio.authify.listeners.LoginProtocolListener;
import org.mapplestudio.authify.listeners.PlayerSecurityListener;
import org.mapplestudio.authify.managers.AuthManager;

public final class Authify extends JavaPlugin {

    private DatabaseManager databaseManager;
    private AuthManager authManager;
    private ProtocolManager protocolManager;
    private boolean debugMode;

    @Override
    public void onEnable() {
        // Load Configuration
        saveDefaultConfig();
        reloadConfig(); // Ensure we have the latest values
        this.debugMode = getConfig().getBoolean("debug", false);

        // Initialize Managers
        this.databaseManager = new DatabaseManager(this);
        this.authManager = new AuthManager();
        this.protocolManager = ProtocolLibrary.getProtocolManager();

        // Register Listeners
        // 1. Login Protocol Listener (Ini Packet Listener, jadi pakai ProtocolManager)
        LoginProtocolListener loginListener = new LoginProtocolListener(this, databaseManager, authManager);
        protocolManager.addPacketListener(loginListener);

        // 2. Security Listener (Ini SEKARANG cuma Bukkit Listener biasa, JANGAN pakai protocolManager)
        PlayerSecurityListener securityListener = new PlayerSecurityListener(this, authManager);
        // HAPUS BARIS INI: protocolManager.addPacketListener(securityListener);
        Bukkit.getPluginManager().registerEvents(securityListener, this);

        // Register Commands
        getCommand("register").setExecutor(new RegisterCommand(this, databaseManager, authManager));
        getCommand("login").setExecutor(new LoginCommand(this, databaseManager, authManager));

        getLogger().info("Authify has been enabled!");
        if (debugMode) {
            getLogger().info("Debug mode is ENABLED.");
        }
    }

    @Override
    public void onDisable() {
        if (databaseManager != null) {
            databaseManager.close();
        }
        getLogger().info("Authify has been disabled!");
    }

    public boolean isDebug() {
        return debugMode;
    }

    public void debug(String message) {
        if (debugMode) {
            getLogger().info("[DEBUG] " + message);
        }
    }
}