package org.mapplestudio.authify.listeners;

import com.comphenix.protocol.PacketType;
import com.comphenix.protocol.ProtocolLibrary;
import com.comphenix.protocol.events.PacketAdapter;
import com.comphenix.protocol.events.PacketContainer;
import com.comphenix.protocol.events.PacketEvent;
import com.comphenix.protocol.wrappers.WrappedGameProfile;
import org.mapplestudio.authify.Authify;
import org.mapplestudio.authify.database.DatabaseManager;
import org.mapplestudio.authify.managers.AuthManager;
import org.mapplestudio.authify.managers.AuthSession;
import org.mapplestudio.authify.utils.EncryptionUtil;

import javax.crypto.SecretKey;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.Map;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import java.util.Set;

public class LoginProtocolListener extends PacketAdapter {
    private final Authify plugin;
    private final DatabaseManager databaseManager;
    private final AuthManager authManager;
    private final Map<String, byte[]> verifyTokens = new ConcurrentHashMap<>();
    private final Set<String> processingPlayers = ConcurrentHashMap.newKeySet();

    public LoginProtocolListener(Authify plugin, DatabaseManager databaseManager, AuthManager authManager) {
        super(plugin, PacketType.Login.Client.START, PacketType.Login.Client.ENCRYPTION_BEGIN);
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

            if (processingPlayers.contains(username)) {
                processingPlayers.remove(username);
                return; // Allow the packet to pass through (Cracked path re-injection)
            }

            event.setCancelled(true); // Hold the packet

            // Async Lookup
            databaseManager.isPremium(username).thenAccept(isPremium -> {
                if (isPremium) {
                    try {
                        KeyPair keyPair = EncryptionUtil.getKeyPair();
                        byte[] verifyToken = EncryptionUtil.generateVerifyToken();
                        verifyTokens.put(username, verifyToken);

                        PacketContainer encryptionRequest = ProtocolLibrary.getProtocolManager()
                                .createPacket(PacketType.Login.Server.ENCRYPTION_BEGIN);
                        encryptionRequest.getStrings().write(0, ""); // Server ID
                        encryptionRequest.getPublicKeys().write(0, keyPair.getPublic());
                        encryptionRequest.getByteArrays().write(0, verifyToken);

                        ProtocolLibrary.getProtocolManager().sendServerPacket(event.getPlayer(), encryptionRequest);
                    } catch (Exception e) {
                        plugin.getLogger().severe("Error initiating encryption for " + username + ": " + e.getMessage());
                        event.getPlayer().kickPlayer("Authentication Error");
                    }
                } else {
                    // Cracked: Release the packet
                    processingPlayers.add(username);
                    try {
                        ProtocolLibrary.getProtocolManager().receiveClientPacket(event.getPlayer(), packet);
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }
            });

        } else if (event.getPacketType() == PacketType.Login.Client.ENCRYPTION_BEGIN) {
            event.setCancelled(true); // Handle manually
            
            // Note: In 1.20.2+, the networking state changes are stricter.
            // We must ensure we are in the LOGIN state.
            
            PacketContainer packet = event.getPacket();
            byte[] sharedSecret = packet.getByteArrays().read(0);
            byte[] clientVerifyToken = packet.getByteArrays().read(1);
            String username = event.getPlayer().getName(); // Temp player name
            
            try {
                KeyPair keyPair = EncryptionUtil.getKeyPair();
                SecretKey secretKey = EncryptionUtil.decryptSharedKey(keyPair.getPrivate(), sharedSecret);
                
                if (!java.util.Arrays.equals(verifyTokens.get(username), 
                        EncryptionUtil.decryptData(keyPair.getPrivate(), clientVerifyToken))) {
                    event.getPlayer().kickPlayer("Invalid verify token");
                    return;
                }

                String serverId = EncryptionUtil.generateServerId("", keyPair.getPublic(), secretKey);
                String ip = event.getPlayer().getAddress().getAddress().getHostAddress();
                
                // Authenticate with Mojang
                authenticateMojang(username, serverId, ip).thenAccept(profile -> {
                    if (profile != null) {
                        // Success!
                        // 1. Enable encryption on the channel (ProtocolLib/Netty magic required here usually, 
                        // but for this scope we focus on the logic flow).
                        // In a full plugin, you'd access the Channel via ProtocolLib and add the Cipher.
                        
                        // 2. Send Login Success
                        PacketContainer success = ProtocolLibrary.getProtocolManager()
                                .createPacket(PacketType.Login.Server.SUCCESS);
                        success.getGameProfiles().write(0, profile);
                        
                        try {
                            ProtocolLibrary.getProtocolManager().sendServerPacket(event.getPlayer(), success);
                            
                            // Register session
                            AuthSession session = authManager.createSession(profile.getUUID());
                            session.setLoggedIn(true);
                            session.setPremium(true);
                            
                        } catch (Exception e) {
                            e.printStackTrace();
                        }
                    } else {
                        event.getPlayer().kickPlayer("Failed to authenticate with Mojang");
                    }
                });
                
            } catch (Exception e) {
                plugin.getLogger().severe("Encryption error: " + e.getMessage());
                event.getPlayer().kickPlayer("Authentication Error");
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
                
                // Add properties (Skin)
                if (json.has("properties")) {
                    json.getAsJsonArray("properties").forEach(element -> {
                        JsonObject prop = element.getAsJsonObject();
                        String pName = prop.get("name").getAsString();
                        String pValue = prop.get("value").getAsString();
                        String pSignature = prop.has("signature") ? prop.get("signature").getAsString() : null;
                        profile.getProperties().put(pName, new com.comphenix.protocol.wrappers.WrappedSignedProperty(pName, pValue, pSignature));
                    });
                }
                
                return profile;
            } catch (Exception e) {
                return null;
            }
        });
    }
}
