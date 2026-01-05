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

public class LoginCommand implements CommandExecutor {
    private final Authify plugin;
    private final DatabaseManager databaseManager;
    private final AuthManager authManager;

    public LoginCommand(Authify plugin, DatabaseManager databaseManager, AuthManager authManager) {
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

        if (args.length != 1) {
            player.sendMessage(getMessage("usage-login"));
            return true;
        }

        String password = args[0];

        databaseManager.getPasswordHash(player.getName()).thenAccept(hashedPassword -> {
            if (hashedPassword == null) {
                player.sendMessage(getMessage("not-registered"));
                return;
            }

            BCrypt.Result result = BCrypt.verifyer().verify(password.toCharArray(), hashedPassword);
            if (result.verified) {
                AuthSession session = authManager.createSession(player.getUniqueId());
                session.setLoggedIn(true);
                session.setPremium(false);
                
                // FIX: Force teleport to refresh chunks and remove void effect
                plugin.getServer().getScheduler().runTask(plugin, () -> {
                    player.teleport(player.getLocation());
                    player.sendMessage(getMessage("login-success"));
                });
            } else {
                player.sendMessage(getMessage("login-failed"));
            }
        });

        return true;
    }
}
