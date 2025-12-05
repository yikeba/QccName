package org.que.core.quecontainer;

import org.que.core.queBlock.QueBaseBlock;
import org.que.crypto.CryptoUtil;

import java.io.RandomAccessFile;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * 容器主类（QueBaseContainer）
 *
 * 功能：
 * 1. 持有容器头（head）
 * 2. 持有容器索引列表（indexList）
 * 3. 支持快速查询（通过地址定位区块）
 * 4. 支持按 offset 精准读取区块
 * 5. 支持 SHA3-256 容器完整性校验
 *
 * 不负责写文件，不负责解析区块 → 这些交给 QueContainerWriter/Reader。
 */
public class QueBaseContainer {

    /** 容器头：包含 containerId, prevHash, timestamp, version 等 */
    public QueContainerHead head;
    // ⭐ 必须：容器内所有区块
    public List<QueBaseBlock> blocks;
    /** 区块索引列表（容器最重要的结构） */
    public List<QueContainerIndexEntry> indexList = new ArrayList<>();

    /** 容器整文件 SHA3-256 校验（尾部存储），初始化时不会自动计算 */
    public String tailHash;
    public Path containerFilePath;
    public QueBaseContainer() {}

    public QueBaseContainer(QueContainerHead head, List<QueContainerIndexEntry> indexList, String tailHash) {
        this.head = head;
        this.indexList = indexList;
        this.tailHash = tailHash;
    }

    // ============================================================
    // 查询能力：按地址 → 匹配区块列表
    // ============================================================

    /**
     * 查询：找出某地址所在的区块索引（可能多个）
     */
    public List<QueContainerIndexEntry> findBlocksByAddress(String address) {
        List<QueContainerIndexEntry> result = new ArrayList<>();

        for (QueContainerIndexEntry entry : indexList) {
            if (entry.containsAddress(address)) {
                result.add(entry);
            }
        }
        return result;
    }

    /**
     * 查询：通过 blockNumber 直接找 index
     */
    public QueContainerIndexEntry findIndexByBlockNumber(long blockNumber) {
        for (QueContainerIndexEntry entry : indexList) {
            if (entry.blockNumber == blockNumber) {
                return entry;
            }
        }
        return null;
    }

    // ============================================================
    // 文件读取能力：按 offset + length 精准读取区块
    // ============================================================

    /**
     * 精准读取某个区块的二进制内容（不会解析）
     */
    public byte[] readBlockBytes(RandomAccessFile raf, QueContainerIndexEntry entry) throws Exception {
        raf.seek(entry.offset);
        byte[] buf = new byte[(int) entry.length];
        raf.readFully(buf);
        return buf;
    }

    // ============================================================
    // 容器完整性校验（比对 tail SHA3）
    // ============================================================

    /**
     * 校验容器文件是否被篡改（比对尾部 SHA3 与重新计算的 SHA3）
     */
    public boolean verifyContainerIntegrity(byte[] fullContainerBytes) {
        String hash = CryptoUtil.sha3256Hex(fullContainerBytes);
        return hash.equalsIgnoreCase(tailHash);
    }

    @Override
    public String toString() {
        return "QueBaseContainer{" +
                "head=" + head +
                ", indexListSize=" + (indexList == null ? 0 : indexList.size()) +
                ", tailHash='" + tailHash + '\'' +
                '}';
    }
}
