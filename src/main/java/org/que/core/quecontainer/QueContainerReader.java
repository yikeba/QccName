package org.que.core.quecontainer;

import com.alibaba.fastjson2.JSON;
import org.que.core.queBlock.QueBaseBlock;
import org.que.crypto.CryptoUtil;

import java.io.File;
import java.nio.file.Files;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * 容器读取类（JSON 模式）
 *
 * 负责：
 *  1. 从文件读取容器 JSON
 *  2. 解析出 head / indexList / blocks / tailHash
 *  3. 校验 tailHash（可选）
 *  4. 提供按地址、按区块号等查询区块的能力
 */
public class QueContainerReader {

    private final File file;
    private final QueBaseContainer container;
    private final List<QueBaseBlock> blocks; // 当前容器内的所有区块（JSON 版）

    public QueContainerReader(File file) throws Exception {
        this.file = file;

        // 1) 读取整个文件为字符串（JSON 测试网版本）
        String json = Files.readString(file.toPath(), StandardCharsets.UTF_8);

        // 2) 解析为 DTO
        QueContainerFileDTO dto = JSON.parseObject(json, QueContainerFileDTO.class);
        if (dto == null || dto.head == null || dto.indexList == null) {
            throw new IllegalStateException("容器文件格式错误：head 或 indexList 缺失");
        }

        // 3) 容器完整性校验（可选）
        String calcHash = calcContentHash(dto.head, dto.indexList, dto.blocks);
        if (!calcHash.equalsIgnoreCase(dto.tailHash)) {
            throw new IllegalStateException("容器完整性校验失败：tailHash 不匹配");
        }

        // 4) 构造内存中的容器对象
        this.blocks = dto.blocks != null ? dto.blocks : new ArrayList<>();
        this.container = new QueBaseContainer(dto.head, dto.indexList, dto.tailHash);
    }

    /**
     * 重新计算 head + indexList + blocks 的 SHA3-256，用于校验 tailHash
     */
    private String calcContentHash(QueContainerHead head,
                                   List<QueContainerIndexEntry> indexList,
                                   List<QueBaseBlock> blocks) {

        QueContainerFileDTO tmp = new QueContainerFileDTO();
        tmp.head = head;
        tmp.indexList = indexList;
        tmp.blocks = blocks;
        tmp.tailHash = null; // 计算时不包含 tailHash 自己

        String contentJson = JSON.toJSONString(tmp);
        return CryptoUtil.sha3256Hex(contentJson.getBytes(StandardCharsets.UTF_8));
    }

    // =============== 对外暴露的一些查询能力 ===============

    /** 获取容器头 */
    public QueContainerHead getHead() {
        return container.head;
    }

    /** 获取索引列表 */
    public List<QueContainerIndexEntry> getIndexList() {
        return container.indexList;
    }

    /** 获取所有区块（JSON 模式全部在内存） */
    public List<QueBaseBlock> getBlocks() {
        return blocks;
    }

    /** 按地址查询：返回“可能包含该地址”的索引项列表（用 bloomFilter 判断） */
    public List<QueContainerIndexEntry> findBlocksByAddress(String address) {
        return container.findBlocksByAddress(address);
    }

    /** 按区块高度查询索引项 */
    public QueContainerIndexEntry findIndexByBlockNumber(long blockNumber) {
        return container.findIndexByBlockNumber(blockNumber);
    }

    /** 按区块高度拿到完整区块（JSON 模式直接在内存找） */
    public QueBaseBlock getBlockByNumber(long blockNumber) {
        // 很简单：遍历 blocks 找 head.blockNumber == blockNumber 的
        for (QueBaseBlock block : blocks) {
            if (block.head != null && block.head.blockNumber == blockNumber) {
                return block;
            }
        }
        return null;
    }

    @Override
    public String toString() {
        return "QueContainerReader{" +
                "file=" + file.getName() +
                ", head=" + container.head +
                ", indexSize=" + container.indexList.size() +
                ", blockCount=" + (blocks == null ? 0 : blocks.size()) +
                '}';
    }
}


class QueContainerFileDTO {
    public QueContainerHead head;
    public List<QueContainerIndexEntry> indexList;
    public List<QueBaseBlock> blocks;
    public String tailHash;
}