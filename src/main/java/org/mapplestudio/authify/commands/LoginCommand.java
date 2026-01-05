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

public class LoginCommand implements CommandExecutor {
    private final DatabaseManager databaseManager;
    private final AuthManager authManager;

    public LoginCommand(DatabaseManager databaseManager, AuthManager authManager) {
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

        if (args.length != 1) {
            player.sendMessage(ChatColor.RED + "Usage: /login <password>");
            return true;
        }

        String password = args[0];

        databaseManager.getPasswordHash(player.getName()).thenAccept(hashedPassword -> {
            if (hashedPassword == null) {
                player.sendMessage(ChatColor.RED + "You are not registered. Use /register <password> <confirm>.");
                return;
            }

            BCrypt.Result result = BCrypt.verifyer().verify(password.toCharArray(), hashedPassword);
            if (result.verified) {
                AuthSession session = authManager.createSession(player.getUniqueId());
                session.setLoggedIn(true);
                session.setPremium(false);
                
                player.sendMessage(ChatColor.GREEN + "Successfully logged in!");
            } else {
                player.sendMessage(ChatColor.RED + "Incorrect password.");
            }
        });

        return true;
    }
}
