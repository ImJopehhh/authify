package org.mapplestudio.authify.commands;

import at.favre.lib.crypto.bcrypt.BCrypt;
import org.bukkit.ChatColor;
import org.bukkit.command.Command;
import org.bukkit.command.CommandExecutor;
import org.bukkit.command.CommandSender;
import org.bukkit.entity.Player;
import org.mapplestudio.authify.Authify;
import org.mapplestudio.authify.database.DatabaseManager;
import org.mapplestudio.authify.managers.AuthManager;
import org.mapplestudio.authify.managers.AuthSession;

public class RegisterCommand implements CommandExecutor {
    private final Authify plugin;
    private final DatabaseManager databaseManager;
    private final AuthManager authManager;

    public RegisterCommand(Authify plugin, DatabaseManager databaseManager, AuthManager authManager) {
        this.plugin = plugin;
        this.databaseManager = databaseManager;
        this.authManager = authManager;
    }

    private String getMessage(String path) {
        String msg = plugin.getConfig().getString("messages." + path);
        if (msg == null) return "";
        String prefix = plugin.getConfig().getString("messages.prefix", "");
        return ChatColor.translateAlternateColorCodes('&', prefix + msg);
    }

    @Override
    public boolean onCommand(CommandSender sender, Command command, String label, String[] args) {
        if (!(sender instanceof Player player)) {
            sender.sendMessage(getMessage("only-players"));
            return true;
        }

        if (authManager.isAuthenticated(player.getUniqueId())) {
            player.sendMessage(getMessage("already-logged-in"));
            return true;
        }

        if (args.length != 2) {
            player.sendMessage(getMessage("usage-register"));
            return true;
        }

        String password = args[0];
        String confirm = args[1];

        if (!password.equals(confirm)) {
            player.sendMessage(getMessage("password-mismatch"));
            return true;
        }

        databaseManager.getPasswordHash(player.getName()).thenAccept(existingHash -> {
            if (existingHash != null) {
                player.sendMessage(getMessage("already-registered"));
                return;
            }

            String hashedPassword = BCrypt.withDefaults().hashToString(12, password.toCharArray());
            String ip = player.getAddress().getAddress().getHostAddress();

            databaseManager.registerUser(player.getUniqueId(), player.getName(), hashedPassword, ip).thenRun(() -> {
                AuthSession session = authManager.createSession(player.getUniqueId());
                session.setLoggedIn(true);
                session.setPremium(false); // Registered users are treated as cracked/offline
                
                player.sendMessage(getMessage("register-success"));
            });
        });

        return true;
    }
}
