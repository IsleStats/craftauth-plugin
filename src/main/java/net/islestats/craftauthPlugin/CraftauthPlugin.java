package net.islestats.craftauthPlugin;

import com.google.gson.JsonObject;
import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.format.NamedTextColor;
import org.bukkit.event.EventHandler;
import org.bukkit.event.Listener;
import org.bukkit.event.player.AsyncPlayerPreLoginEvent;
import org.bukkit.plugin.java.JavaPlugin;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

public class CraftauthPlugin extends JavaPlugin implements Listener {
    private static final long CODE_TTL_MS = Duration.ofMinutes(5).toMillis();

    private record CachedCode(String code, long expiresAt) {}

    private final Map<UUID, CachedCode> codeCache = new ConcurrentHashMap<>();
    private final SecureRandom random = new SecureRandom();
    private final HttpClient http = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(5))
            .build();

    private String apiUrl;
    private String token;

    @Override
    public void onEnable() {
        saveDefaultConfig();
        apiUrl = getConfig().getString("apiurl");
        token = getConfig().getString("token");

        if (apiUrl == null || apiUrl.isBlank() || token == null || token.isBlank()) {
            getSLF4JLogger().error("config.yml has incomplete information, disabling.");
            getServer().getPluginManager().disablePlugin(this);
            return;
        }

        getServer().getPluginManager().registerEvents(this, this);
    }

    @EventHandler
    public void onPreLogin(AsyncPlayerPreLoginEvent event) {
        UUID uuid = event.getUniqueId();
        String name = event.getName();
        getSLF4JLogger().info("Player {} [{}] sent a request.", name, uuid);

        long now = System.currentTimeMillis();
        CachedCode cached = codeCache.get(uuid);
        String code;

        if (cached != null && cached.expiresAt() > now) {
            code = cached.code();
            getSLF4JLogger().info("Retrieved {} [{}]'s code, {}", name, uuid, code);
        } else {
            codeCache.values().removeIf(c -> c.expiresAt() <= now); // lazy cleanup
            code = generateCode();

            try {
                post(uuid, code);
            } catch (Exception e) {
                getSLF4JLogger().error("Failed to post code for {} [{}]", name, uuid, e);
                event.disallow(AsyncPlayerPreLoginEvent.Result.KICK_OTHER,
                        Component.text("Could not generate a linking code, try again later.", NamedTextColor.RED));
                return;
            }

            codeCache.put(uuid, new CachedCode(code, now + CODE_TTL_MS));
            getSLF4JLogger().info("Generated and posted {} [{}]'s code, {}", name, uuid, code);
        }

        event.disallow(AsyncPlayerPreLoginEvent.Result.KICK_OTHER,
                Component.text("Your linking code is ")
                        .append(Component.text(code, NamedTextColor.GOLD))
                        .appendNewline()
                        .append(Component.text("It will expire in 5 minutes", NamedTextColor.GRAY)));
    }

    private String generateCode() {
        StringBuilder sb = new StringBuilder(5);
        for (int i = 0; i < 5; i++) sb.append(Character.forDigit(random.nextInt(16), 16));
        return sb.toString();
    }

    private void post(UUID uuid, String code) throws Exception {
        JsonObject body = new JsonObject();
        body.addProperty("code", code);
        body.addProperty("uuid", uuid.toString());

        getSLF4JLogger().info("Post request body {}", body.toString());
        HttpRequest request = HttpRequest.newBuilder(URI.create(apiUrl))
                .timeout(Duration.ofSeconds(5))
                .header("Content-Type", "application/json")
                .header("Authorization", token)
                .POST(HttpRequest.BodyPublishers.ofString(body.toString()))
                .build();

        HttpResponse<Void> response = http.send(request, HttpResponse.BodyHandlers.discarding());
        if (response.statusCode() / 100 != 2) {
            throw new IllegalStateException("API returned HTTP " + response.statusCode());
        }
    }
}