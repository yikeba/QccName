package org.que.core.cache;

import org.iq80.leveldb.*;
import org.iq80.leveldb.impl.Iq80DBFactory;
import net.jpountz.lz4.*;

import java.io.File;
import java.util.LinkedHashMap;
import java.util.Map;
import org.que.config.QubePath;

/**
 * AddressCache （主网稳定版）
 * 使用纯Java LevelDB + LZ4 + LRU
 * 存储路径：~/qubechain/cache/addressdb
 */
public class AddressCache {

    private final Map<String, byte[]> lruCache;
    private final int MAX_LRU = 10_000;

    private final DB db;

    private final LZ4Factory lz4Factory = LZ4Factory.fastestJavaInstance();
    private final LZ4Compressor compressor = lz4Factory.fastCompressor();
    private final LZ4FastDecompressor decompressor = lz4Factory.fastDecompressor();

    // Dilithium5 公钥 encoded 长度（你系统日志反复确认是 5184）
    private static final int PUBLIC_KEY_LEN = 5184;


    public AddressCache() throws Exception {

        // 统一路径：~/qubechain/cache/addressdb
        String dbPath = QubePath.CACHE_DIR.resolve("addressdb").toString();

        this.lruCache = new LinkedHashMap<>(MAX_LRU, 0.75f, true) {
            @Override
            protected boolean removeEldestEntry(Map.Entry eldest) {
                return size() > MAX_LRU;
            }
        };

        Options options = new Options();
        options.createIfMissing(true);

        this.db = Iq80DBFactory.factory.open(new File(dbPath), options);

        System.out.println("AddressCache 启动：path=" + dbPath);
    }


    public void put(String address, byte[] publicKey) {
        try {
            byte[] compressed = compress(publicKey);
            db.put(address.getBytes(), compressed);

            synchronized (lruCache) {
                lruCache.put(address, publicKey);
            }

        } catch (Exception e) {
            throw new RuntimeException("AddressCache PUT failed", e);
        }
    }


    public byte[] get(String address) {
        try {
            synchronized (lruCache) {
                byte[] pk = lruCache.get(address);
                if (pk != null) return pk;
            }

            byte[] compressed = db.get(address.getBytes());
            if (compressed == null) return null;

            byte[] pk = decompress(compressed);

            synchronized (lruCache) {
                lruCache.put(address, pk);
            }

            return pk;

        } catch (Exception e) {
            throw new RuntimeException("AddressCache GET failed", e);
        }
    }


    private byte[] compress(byte[] data) {
        int maxLen = compressor.maxCompressedLength(data.length);
        byte[] out = new byte[maxLen];
        int len = compressor.compress(data, 0, data.length, out, 0, maxLen);

        byte[] result = new byte[len];
        System.arraycopy(out, 0, result, 0, len);
        return result;
    }

    private byte[] decompress(byte[] compressed) {
        byte[] result = new byte[PUBLIC_KEY_LEN];
        decompressor.decompress(compressed, 0, result, 0, PUBLIC_KEY_LEN);
        return result;
    }

    public void close() throws Exception {
        db.close();
    }
}
