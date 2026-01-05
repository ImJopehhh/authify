package org.mapplestudio.authify.listeners;

import com.comphenix.protocol.PacketType;
import com.comphenix.protocol.ProtocolLibrary;
import com.comphenix.protocol.events.ListenerPriority;
import com.comphenix.protocol.events.PacketAdapter;
import com.comphenix.protocol.events.PacketContainer;
import com.comphenix.protocol.events.PacketEvent;
import com.comphenix.protocol.wrappers.WrappedGameProfile;
import com.comphenix.protocol.wrappers.WrappedSignedProperty;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.mapplestudio.authify.Authify;
import org.mapplestudio.authify.database.DatabaseManager;
import org.mapplestudio.authify.managers.AuthManager;
import org.mapplestudio.authify.managers.AuthSession;
import org.mapplestudio.authify.utils.EncryptionUtil;

import javax.crypto.SecretKey;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

public class LoginProtocolListener extends PacketAdapter {
    private final Authify plugin;
    private final DatabaseManager databaseManager;
    private final AuthManager authManager;
    private final Map<String, byte[]> verifyTokens = new ConcurrentHashMap<>();
    private final Set<String> processingPlayers = ConcurrentHashMap.newKeySet();
    // Store original login packet to re-inject later
    private final Map<String, PacketContainer> pendingLoginPackets = new ConcurrentHashMap<>();
    // Track connection identity by IP/Port since Player name is not yet available
    private final Map<InetSocketAddress, String> pendingConnections = new ConcurrentHashMap<>();

    public LoginProtocolListener(Authify plugin, DatabaseManager databaseManager, AuthManager authManager) {
        super(plugin, ListenerPriority.HIGHEST, PacketType.Login.Client.START, PacketType.Login.Client.ENCRYPTION_BEGIN);
        this.plugin = plugin;
        this.databaseManager = databaseManager;
        this.authManager = authManager;
    }

    @Override
    public void onPacketReceiving(PacketEvent event) {
        if (event.getPacketType() == PacketType.Login.Client.START) {
            PacketContainer packet = event.getPacket();
            
            // FIX: In 1.20.2+, LoginStart uses Strings and UUIDs directly
            String username = packet.getStrings().read(0);
            UUID uuid = packet.getUUIDs().read(0);
            InetSocketAddress address = event.getPlayer().getAddress();
            
            plugin.debug("Received LoginStart for: " + username + " (" + uuid + ") from " + address);

            // Anti-Loop: If we already marked this player as processed, let the packet pass
            if (processingPlayers.contains(username)) {
                plugin.debug("Player " + username + " is already processed. Allowing packet.");
                processingPlayers.remove(username);
                pendingConnections.remove(address); // Cleanup
                return; 
            }

            // 1. HOLD the packet (Stop server from assigning Offline UUID)
            event.setCancelled(true);
            pendingLoginPackets.put(username, packet);
            pendingConnections.put(address, username); // Map IP to Username
            plugin.debug("Held LoginStart packet for " + username);

            // 2. Async Lookup
            databaseManager.isPremium(username).thenAccept(isPremium -> {
                plugin.debug("Database lookup for " + username + ": Premium=" + isPremium);
                
                if (isPremium == null) {
                    // User not in DB -> Check Mojang API
                    checkMojangApi(username).thenAccept(hasMojangProfile -> {
                        plugin.debug("Mojang API check for " + username + ": " + hasMojangProfile);
                        if (hasMojangProfile) {
                            initiateEncryption(event.getPlayer(), username);
                        } else {
                            releasePacket(event.getPlayer(), username, packet);
                        }
                    });
                } else if (isPremium) {
                    initiateEncryption(event.getPlayer(), username);
                } else {
                    releasePacket(event.getPlayer(), username, packet);
                }
            });

        } else if (event.getPacketType() == PacketType.Login.Client.ENCRYPTION_BEGIN) {
            // 4. Handle Encryption Response (Premium Only)
            event.setCancelled(true); // We handle this manually
            
            InetSocketAddress address = event.getPlayer().getAddress();
            String username = pendingConnections.get(address);

            if (username == null) {
                plugin.debug("Received Encryption Response from unknown connection: " + address);
                event.getPlayer().kickPlayer(plugin.getConfig().getString("messages.kick-auth-failed", "Authentication Failed"));
                return;
            }

            PacketContainer packet = event.getPacket();
            byte[] sharedSecret = packet.getByteArrays().read(0);
            byte[] clientVerifyToken = packet.getByteArrays().read(1);
            
            plugin.debug("Received Encryption Response from " + username);
            
            try {
                KeyPair keyPair = EncryptionUtil.getKeyPair();
                SecretKey secretKey = EncryptionUtil.decryptSharedKey(keyPair.getPrivate(), sharedSecret);
                
                if (!java.util.Arrays.equals(verifyTokens.get(username), 
                        EncryptionUtil.decryptData(keyPair.getPrivate(), clientVerifyToken))) {
                    plugin.debug("Verify token mismatch for " + username);
                    event.getPlayer().kickPlayer(plugin.getConfig().getString("messages.kick-auth-failed", "Authentication Failed"));
                    cleanup(username, address);
                    return;
                }

                String serverId = EncryptionUtil.generateServerId("", keyPair.getPublic(), secretKey);
                String ip = address.getAddress().getHostAddress();
                
                // 5. Authenticate with Mojang
                plugin.debug("Authenticating " + username + " with Mojang...");
                authenticateMojang(username, serverId, ip).thenAccept(profile -> {
                    if (profile != null) {
                        plugin.debug("Mojang Auth Success for " + username + ". UUID: " + profile.getUUID());
                        // 6. Success: Re-inject Login Start with REAL UUID
                        PacketContainer originalLoginPacket = pendingLoginPackets.remove(username);
                        if (originalLoginPacket != null) {
                            // Update the profile in the original packet
                            originalLoginPacket.getUUIDs().write(0, profile.getUUID());
                            
                            // Mark as processed so we don't intercept it again
                            processingPlayers.add(username);
                            
                            try {
                                plugin.debug("Re-injecting LoginStart for premium user " + username + " with UUID " + profile.getUUID());
                                ProtocolLibrary.getProtocolManager().receiveClientPacket(event.getPlayer(), originalLoginPacket);
                                
                                AuthSession session = authManager.createSession(profile.getUUID());
                                session.setLoggedIn(true);
                                session.setPremium(true);
                            } catch (Exception e) {
                                e.printStackTrace();
                            }
                        } else {
                             event.getPlayer().kickPlayer(plugin.getConfig().getString("messages.kick-session-expired", "Session Expired"));
                        }
                    } else {
                        plugin.debug("Mojang Auth Failed for " + username);
                        event.getPlayer().kickPlayer(plugin.getConfig().getString("messages.kick-auth-failed", "Authentication Failed"));
                    }
                    cleanup(username, address);
                });
                
            } catch (Exception e) {
                plugin.getLogger().severe("Encryption Error: " + e.getMessage());
                event.getPlayer().kickPlayer(plugin.getConfig().getString("messages.kick-encryption-error", "Encryption Error"));
                cleanup(username, address);
            }
        }
    }

    private void cleanup(String username, InetSocketAddress address) {
        if (username != null) {
            verifyTokens.remove(username);
            // pendingLoginPackets.remove(username); // Handled in logic
        }
        if (address != null) {
            pendingConnections.remove(address);
        }
    }

    private void initiateEncryption(org.bukkit.entity.Player player, String username) {
        try {
            KeyPair keyPair = EncryptionUtil.getKeyPair();
            byte[] verifyToken = EncryptionUtil.generateVerifyToken();
            verifyTokens.put(username, verifyToken);

            PacketContainer encryptionRequest = ProtocolLibrary.getProtocolManager()
                    .createPacket(PacketType.Login.Server.ENCRYPTION_BEGIN);
            encryptionRequest.getStrings().write(0, ""); // Server ID
            encryptionRequest.getByteArrays().write(0, keyPair.getPublic().getEncoded());
            encryptionRequest.getByteArrays().write(1, verifyToken);

            ProtocolLibrary.getProtocolManager().sendServerPacket(player, encryptionRequest);
            plugin.debug("Sent Encryption Request to " + username);
        } catch (Exception e) {
            plugin.getLogger().severe("Encryption init failed for " + username);
            player.kickPlayer(plugin.getConfig().getString("messages.kick-auth-failed", "Authentication Failed"));
            pendingLoginPackets.remove(username);
            pendingConnections.remove(player.getAddress());
        }
    }

    private void releasePacket(org.bukkit.entity.Player player, String username, PacketContainer packet) {
        processingPlayers.add(username);
        pendingLoginPackets.remove(username);
        // pendingConnections.remove(player.getAddress()); // Will be removed in next START packet check or manually here
        // Actually, since we re-inject, the START packet comes back. 
        // The START packet handler will see 'processingPlayers' and remove the pendingConnection then.
        try {
            plugin.debug("Re-injecting LoginStart for cracked user " + username);
            ProtocolLibrary.getProtocolManager().receiveClientPacket(player, packet);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private java.util.concurrent.CompletableFuture<Boolean> checkMojangApi(String username) {
        return java.util.concurrent.CompletableFuture.supplyAsync(() -> {
            try {
                URL url = new URL("https://api.mojang.com/users/profiles/minecraft/" + username);
                HttpURLConnection connection = (HttpURLConnection) url.openConnection();
                connection.setRequestMethod("GET");
                connection.setConnectTimeout(5000);
                connection.setReadTimeout(5000);
                
                int responseCode = connection.getResponseCode();
                return responseCode == 200;
            } catch (Exception e) {
                plugin.getLogger().warning("Failed to check Mojang API for " + username + ": " + e.getMessage());
                return false; // Fail-safe to cracked
            }
        });
    }

    private java.util.concurrent.CompletableFuture<WrappedGameProfile> authenticateMojang(String username, String serverId, String ip) {
        return java.util.concurrent.CompletableFuture.supplyAsync(() -> {
            try {
                URL url = new URL("https://sessionserver.mojang.com/session/minecraft/hasJoined?username=" 
                        + URLEncoder.encode(username, StandardCharsets.UTF_8) 
                        + "&serverId=" + URLEncoder.encode(serverId, StandardCharsets.UTF_8)
                        + "&ip=" + URLEncoder.encode(ip, StandardCharsets.UTF_8));
                
                BufferedReader reader = new BufferedReader(new InputStreamReader(url.openStream()));
                JsonObject json = JsonParser.parseReader(reader).getAsJsonObject();
                
                String id = json.get("id").getAsString();
                String name = json.get("name").getAsString();
                UUID uuid = UUID.fromString(id.replaceFirst(
                        "(\\w{8})(\\w{4})(\\w{4})(\\w{4})(\\w{12})", "$1-$2-$3-$4-$5"));
                
                WrappedGameProfile profile = new WrappedGameProfile(uuid, name);
                
                if (json.has("properties")) {
                    json.getAsJsonArray("properties").forEach(element -> {
                        JsonObject prop = element.getAsJsonObject();
                        String pName = prop.get("name").getAsString();
                        String pValue = prop.get("value").getAsString();
                        String pSignature = prop.has("signature") ? prop.get("signature").getAsString() : null;
                        profile.getProperties().put(pName, new WrappedSignedProperty(pName, pValue, pSignature));
                    });
                }
                return profile;
            } catch (Exception e) {
                return null;
            }
        });
    }
}
