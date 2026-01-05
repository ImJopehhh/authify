package org.mapplestudio.authify.database;

import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import org.mapplestudio.authify.Authify;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;

public class DatabaseManager {
    private final Authify plugin;
    private HikariDataSource dataSource;
    private final boolean isMySQL;

    public DatabaseManager(Authify plugin) {
        this.plugin = plugin;
        // In a real scenario, read from config. Assuming SQLite for default/simplicity if config not present
        this.isMySQL = false; 
        connect();
        createTables();
    }

    private void connect() {
        HikariConfig config = new HikariConfig();
        if (isMySQL) {
            config.setJdbcUrl("jdbc:mysql://localhost:3306/authify");
            config.setUsername("root");
            config.setPassword("password");
            config.addDataSourceProperty("cachePrepStmts", "true");
            config.addDataSourceProperty("prepStmtCacheSize", "250");
            config.addDataSourceProperty("prepStmtCacheSqlLimit", "2048");
        } else {
            config.setJdbcUrl("jdbc:sqlite:" + plugin.getDataFolder() + "/database.db");
            config.setDriverClassName("org.sqlite.JDBC");
        }
        config.setMaximumPoolSize(10);
        dataSource = new HikariDataSource(config);
    }

    private void createTables() {
        try (Connection conn = dataSource.getConnection();
             PreparedStatement ps = conn.prepareStatement(
                     "CREATE TABLE IF NOT EXISTS authify_users (" +
                             "uuid VARCHAR(36) PRIMARY KEY, " +
                             "username VARCHAR(16) NOT NULL, " +
                             "password VARCHAR(255), " +
                             "premium BOOLEAN DEFAULT FALSE, " +
                             "ip VARCHAR(45)" +
                             ")")) {
            ps.executeUpdate();
        } catch (SQLException e) {
            plugin.getLogger().severe("Could not create tables: " + e.getMessage());
        }
    }

    public CompletableFuture<Boolean> isPremium(String username) {
        return CompletableFuture.supplyAsync(() -> {
            try (Connection conn = dataSource.getConnection();
                 PreparedStatement ps = conn.prepareStatement("SELECT premium FROM authify_users WHERE username = ?")) {
                ps.setString(1, username);
                try (ResultSet rs = ps.executeQuery()) {
                    if (rs.next()) {
                        return rs.getBoolean("premium");
                    }
                }
            } catch (SQLException e) {
                e.printStackTrace();
            }
            return false; // Default to cracked if not found
        });
    }

    public void close() {
        if (dataSource != null) {
            dataSource.close();
        }
    }
}
