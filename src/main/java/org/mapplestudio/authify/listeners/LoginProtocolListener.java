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
            WrappedGameProfile profile = packet.getGameProfiles().read(0);
            String username = profile.getName();

            // Anti-Loop: If we already marked this player as processed, let the packet pass
            if (processingPlayers.contains(username)) {
                processingPlayers.remove(username);
                return; 
            }

            // 1. HOLD the packet (Stop server from assigning Offline UUID)
            event.setCancelled(true);
            pendingLoginPackets.put(username, packet);

            // 2. Async Lookup
            databaseManager.isPremium(username).thenAccept(isPremium -> {
                if (isPremium) {
                    // 3a. Premium: Initiate Encryption Flow
                    try {
                        KeyPair keyPair = EncryptionUtil.getKeyPair();
                        byte[] verifyToken = EncryptionUtil.generateVerifyToken();
                        verifyTokens.put(username, verifyToken);

                        PacketContainer encryptionRequest = ProtocolLibrary.getProtocolManager()
                                .createPacket(PacketType.Login.Server.ENCRYPTION_BEGIN);
                        encryptionRequest.getStrings().write(0, ""); // Server ID
                        // FIX: Use getByteArrays() for Public Key in 1.21+
                        encryptionRequest.getByteArrays().write(0, keyPair.getPublic().getEncoded());
                        encryptionRequest.getByteArrays().write(1, verifyToken);

                        ProtocolLibrary.getProtocolManager().sendServerPacket(event.getPlayer(), encryptionRequest);
                    } catch (Exception e) {
                        plugin.getLogger().severe("Encryption init failed for " + username);
                        event.getPlayer().kickPlayer(plugin.getConfig().getString("messages.kick-auth-failed", "Authentication Failed"));
                        pendingLoginPackets.remove(username);
                    }
                } else {
                    // 3b. Cracked: Re-inject packet to let server handle it
                    processingPlayers.add(username);
                    pendingLoginPackets.remove(username);
                    try {
                        ProtocolLibrary.getProtocolManager().receiveClientPacket(event.getPlayer(), packet);
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }
            });

        } else if (event.getPacketType() == PacketType.Login.Client.ENCRYPTION_BEGIN) {
            // 4. Handle Encryption Response (Premium Only)
            event.setCancelled(true); // We handle this manually
            
            PacketContainer packet = event.getPacket();
            byte[] sharedSecret = packet.getByteArrays().read(0);
            byte[] clientVerifyToken = packet.getByteArrays().read(1);
            String username = event.getPlayer().getName();
            
            try {
                KeyPair keyPair = EncryptionUtil.getKeyPair();
                SecretKey secretKey = EncryptionUtil.decryptSharedKey(keyPair.getPrivate(), sharedSecret);
                
                if (!java.util.Arrays.equals(verifyTokens.get(username), 
                        EncryptionUtil.decryptData(keyPair.getPrivate(), clientVerifyToken))) {
                    event.getPlayer().kickPlayer(plugin.getConfig().getString("messages.kick-auth-failed", "Authentication Failed"));
                    return;
                }

                String serverId = EncryptionUtil.generateServerId("", keyPair.getPublic(), secretKey);
                String ip = event.getPlayer().getAddress().getAddress().getHostAddress();
                
                // 5. Authenticate with Mojang
                authenticateMojang(username, serverId, ip).thenAccept(profile -> {
                    if (profile != null) {
                        // 6. Success: Re-inject Login Start with REAL UUID
                        PacketContainer originalLoginPacket = pendingLoginPackets.remove(username);
                        if (originalLoginPacket != null) {
                            // Update the profile in the original packet
                            originalLoginPacket.getGameProfiles().write(0, profile);
                            
                            // Mark as processed so we don't intercept it again
                            processingPlayers.add(username);
                            
                            try {
                                // Note: In a full implementation, you must also enable encryption on the Netty channel here.
                                // ProtocolLib doesn't expose channel encryption easily without NMS or reflection.
                                // For this scope, we assume the server is in offline mode so it won't enforce encryption,
                                // but we have validated the user is premium.
                                
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
                        event.getPlayer().kickPlayer(plugin.getConfig().getString("messages.kick-auth-failed", "Authentication Failed"));
                    }
                });
                
            } catch (Exception e) {
                event.getPlayer().kickPlayer(plugin.getConfig().getString("messages.kick-encryption-error", "Encryption Error"));
            }
        }
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
