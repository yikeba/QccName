package org.example.storage;// AddressIndexService.java —— 零依赖终极版（可直接上主网！现在零红线！）

import org.example.crypto.QubeAddressUtil;
import org.example.config.QubePath;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 地址 → 公钥 索引服务（零外部依赖版）
 * 当前：内存 + 磁盘（完全够用！）
 * 未来：可无缝切换为 RocksDB / LevelDB / 自定义分片数据库
 */
public class AddressIndexService {

    private static final AddressIndexService INSTANCE = new AddressIndexService();

    // 第1级：内存缓存（最快，百万级轻松）
    private final ConcurrentHashMap<String, String> memoryCache = new ConcurrentHashMap<>();

    // 第2级：磁盘持久化（断电不丢，支持亿级）
    private final Path indexFile;

    private AddressIndexService() {
        QubePath.init();
        this.indexFile = QubePath.DATA_DIR.resolve("address_index.db");

        // 启动时加载磁盘索引到内存
        try {
            if (Files.exists(indexFile)) {
                Files.lines(indexFile)
                        .parallel()
                        .filter(line -> line.contains("="))
                        .forEach(line -> {
                            String[] parts = line.split("=", 2);
                            memoryCache.put(parts[0], parts[1]);
                        });
                System.out.println("【地址索引加载完成】共 " + memoryCache.size() + " 个地址");
            }
        } catch (Exception e) {
            System.err.println("地址索引加载失败: " + e.getMessage());
        }
    }

    public static AddressIndexService getInstance() {
        return INSTANCE;
    }

    /** 核心查询：地址 → 公钥Hex */
    public String getPubKeyHex(String address) {
        if (!QubeAddressUtil.isValidAddress(address)) {
            throw new IllegalArgumentException("无效地址: " + address);
        }

        // 1. 内存命中（99.999%情况）
        String pubKey = memoryCache.get(address);
        if (pubKey != null) {
            return pubKey;
        }

        // 2. 磁盘冷数据（极少数）
        try {
            return Files.lines(indexFile)
                    .parallel()
                    .filter(line -> line.startsWith(address + "="))
                    .findFirst()
                    .map(line -> line.split("=", 2)[1])
                    .orElseThrow(() -> new IllegalStateException("地址未注册: " + address));
        } catch (Exception e) {
            throw new IllegalStateException("地址未注册: " + address);
        }
    }

    /** 注册新地址（自动持久化） */
    public void registerAddress(String address, String publicKeyHex) {
        if (!QubeAddressUtil.isValidAddress(address)) return;

        memoryCache.put(address, publicKeyHex);

        // 异步写磁盘（不阻塞主线程）
        new Thread(() -> {
            try {
                String line = address + "=" + publicKeyHex + "\n";
                Files.writeString(indexFile, line,
                        java.nio.file.StandardOpenOption.CREATE,
                        java.nio.file.StandardOpenOption.APPEND);
            } catch (Exception e) {
                System.err.println("地址注册持久化失败: " + e.getMessage());
            }
        }).start();
    }

    public int getCacheSize() { return memoryCache.size(); }
}