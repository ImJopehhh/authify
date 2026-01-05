package org.mapplestudio.authify.listeners;

import com.comphenix.protocol.PacketType;
import com.comphenix.protocol.events.PacketAdapter;
import com.comphenix.protocol.events.PacketEvent;
import org.bukkit.entity.Player;
import org.bukkit.event.EventHandler;
import org.bukkit.event.Listener;
import org.bukkit.event.block.BlockBreakEvent;
import org.bukkit.event.block.BlockPlaceEvent;
import org.bukkit.event.entity.EntityDamageByEntityEvent;
import org.bukkit.event.inventory.InventoryClickEvent;
import org.bukkit.event.player.AsyncPlayerChatEvent;
import org.bukkit.event.player.PlayerCommandPreprocessEvent;
import org.bukkit.event.player.PlayerDropItemEvent;
import org.bukkit.event.player.PlayerInteractEvent;
import org.bukkit.event.player.PlayerJoinEvent;
import org.bukkit.event.player.PlayerMoveEvent;
import org.mapplestudio.authify.Authify;
import org.mapplestudio.authify.managers.AuthManager;

public class PlayerSecurityListener extends PacketAdapter implements Listener {
    private final Authify plugin;
    private final AuthManager authManager;

    public PlayerSecurityListener(Authify plugin, AuthManager authManager) {
        // Intercept OUTGOING world packets
        super(plugin, PacketType.Play.Server.MAP_CHUNK, PacketType.Play.Server.LIGHT_UPDATE);
        this.plugin = plugin;
        this.authManager = authManager;
    }

    @Override
    public void onPacketSending(PacketEvent event) {
        Player player = event.getPlayer();
        // If not authenticated, DO NOT send chunks. World will be empty/void for them.
        if (!authManager.isAuthenticated(player.getUniqueId())) {
            event.setCancelled(true);
        }
    }

    @EventHandler
    public void onJoin(PlayerJoinEvent event) {
        Player player = event.getPlayer();
        if (!authManager.isAuthenticated(player.getUniqueId())) {
            // FIX: Teleport to spawn to prevent floating in void/falling
            // We use a slight delay to ensure the player is fully initialized
            plugin.getServer().getScheduler().runTaskLater(plugin, () -> {
                if (player.isOnline() && !authManager.isAuthenticated(player.getUniqueId())) {
                    player.teleport(player.getWorld().getSpawnLocation());
                }
            }, 1L);
        }
    }

    @EventHandler
    public void onMove(PlayerMoveEvent event) {
        if (!authManager.isAuthenticated(event.getPlayer().getUniqueId())) {
            // Prevent X/Y/Z movement, allow rotation
            if (event.getFrom().getX() != event.getTo().getX() ||
                event.getFrom().getY() != event.getTo().getY() ||
                event.getFrom().getZ() != event.getTo().getZ()) {
                event.setCancelled(true);
            }
        }
    }

    @EventHandler
    public void onChat(AsyncPlayerChatEvent event) {
        if (!authManager.isAuthenticated(event.getPlayer().getUniqueId())) {
            event.setCancelled(true);
        }
    }

    @EventHandler
    public void onCommand(PlayerCommandPreprocessEvent event) {
        if (!authManager.isAuthenticated(event.getPlayer().getUniqueId())) {
            String msg = event.getMessage().toLowerCase();
            if (!msg.startsWith("/login") && !msg.startsWith("/register")) {
                event.setCancelled(true);
            }
        }
    }

    @EventHandler
    public void onBlockBreak(BlockBreakEvent event) {
        if (!authManager.isAuthenticated(event.getPlayer().getUniqueId())) {
            event.setCancelled(true);
        }
    }

    @EventHandler
    public void onBlockPlace(BlockPlaceEvent event) {
        if (!authManager.isAuthenticated(event.getPlayer().getUniqueId())) {
            event.setCancelled(true);
        }
    }

    @EventHandler
    public void onInteract(PlayerInteractEvent event) {
        if (!authManager.isAuthenticated(event.getPlayer().getUniqueId())) {
            event.setCancelled(true);
        }
    }

    @EventHandler
    public void onInventoryClick(InventoryClickEvent event) {
        if (event.getWhoClicked() instanceof Player player) {
            if (!authManager.isAuthenticated(player.getUniqueId())) {
                event.setCancelled(true);
            }
        }
    }

    @EventHandler
    public void onEntityDamageByEntity(EntityDamageByEntityEvent event) {
        if (event.getDamager() instanceof Player player) {
            if (!authManager.isAuthenticated(player.getUniqueId())) {
                event.setCancelled(true);
            }
        }
        if (event.getEntity() instanceof Player player) {
            if (!authManager.isAuthenticated(player.getUniqueId())) {
                event.setCancelled(true);
            }
        }
    }

    @EventHandler
    public void onPlayerDropItem(PlayerDropItemEvent event) {
        if (!authManager.isAuthenticated(event.getPlayer().getUniqueId())) {
            event.setCancelled(true);
        }
    }
}
