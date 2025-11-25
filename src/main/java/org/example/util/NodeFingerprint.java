package org.example.util;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.Base64;

public final class NodeFingerprint {

    private NodeFingerprint() {}

    public static String generate(String nodePublicKey) {
        try {
            String machineId = readFile("/etc/machine-id");
            String sshHostKey = readFile("/etc/ssh/ssh_host_ed25519_key.pub");
            String nodeUUID = readOrCreateUUID();

            String raw = machineId + "|" + sshHostKey + "|" + nodePublicKey + "|" + nodeUUID;
            return sha3Base64(raw);
        } catch (Exception e) {
            throw new RuntimeException("生成节点指纹失败", e);
        }
    }

    private static String readFile(String path) throws IOException {
        return Files.exists(Path.of(path))
                ? Files.readString(Path.of(path)).trim()
                : "";
    }

    private static String readOrCreateUUID() throws IOException {
        Path p = Path.of("/var/lib/qube_chain/node_uuid");

        if (!Files.exists(p)) {
            String uuid = java.util.UUID.randomUUID().toString();
            Files.createDirectories(p.getParent());
            Files.writeString(p, uuid);
            return uuid;
        }
        return Files.readString(p).trim();
    }

    private static String sha3Base64(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA3-256");
            byte[] hash = md.digest(input.getBytes());
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}

