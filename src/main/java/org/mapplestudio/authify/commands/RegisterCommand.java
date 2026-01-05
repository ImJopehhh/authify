package org.mapplestudio.authify.commands;

import at.favre.lib.crypto.bcrypt.BCrypt;
import org.bukkit.ChatColor;
import org.bukkit.command.Command;
import org.bukkit.command.CommandExecutor;
import org.bukkit.command.CommandSender;
import org.bukkit.entity.Player;
import org.mapplestudio.authify.database.DatabaseManager;
import org.mapplestudio.authify.managers.AuthManager;
import org.mapplestudio.authify.managers.AuthSession;

public class RegisterCommand implements CommandExecutor {
    private final DatabaseManager databaseManager;
    private final AuthManager authManager;

    public RegisterCommand(DatabaseManager databaseManager, AuthManager authManager) {
        this.databaseManager = databaseManager;
        this.authManager = authManager;
    }

    @Override
    public boolean onCommand(CommandSender sender, Command command, String label, String[] args) {
        if (!(sender instanceof Player player)) {
            sender.sendMessage(ChatColor.RED + "Only players can use this command.");
            return true;
        }

        if (authManager.isAuthenticated(player.getUniqueId())) {
            player.sendMessage(ChatColor.RED + "You are already logged in.");
            return true;
        }

        if (args.length != 2) {
            player.sendMessage(ChatColor.RED + "Usage: /register <password> <confirm>");
            return true;
        }

        String password = args[0];
        String confirm = args[1];

        if (!password.equals(confirm)) {
            player.sendMessage(ChatColor.RED + "Passwords do not match.");
            return true;
        }

        databaseManager.getPasswordHash(player.getName()).thenAccept(existingHash -> {
            if (existingHash != null) {
                player.sendMessage(ChatColor.RED + "You are already registered. Use /login <password>.");
                return;
            }

            String hashedPassword = BCrypt.withDefaults().hashToString(12, password.toCharArray());
            String ip = player.getAddress().getAddress().getHostAddress();

            databaseManager.registerUser(player.getUniqueId(), player.getName(), hashedPassword, ip).thenRun(() -> {
                AuthSession session = authManager.createSession(player.getUniqueId());
                session.setLoggedIn(true);
                session.setPremium(false); // Registered users are treated as cracked/offline
                
                player.sendMessage(ChatColor.GREEN + "Successfully registered and logged in!");
                // Here you would typically remove blindness/restrictions, but the listener handles it by checking isAuthenticated
            });
        });

        return true;
    }
}
