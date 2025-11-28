package org.que.core.quecontainer;

import com.alibaba.fastjson2.JSON;
import org.que.core.queBlock.QueBaseBlock;
import org.que.crypto.CryptoUtil;
import java.nio.file.Files;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import com.alibaba.fastjson2.JSONObject;
import java.nio.file.Path;
/**
 * 容器读取类（JSON 模式）
 *
 * 负责：
 *  1. 从文件读取容器 JSON
 *  2. 解析出 head / indexList / blocks / tailHash
 *  3. 校验 tailHash（可选）
 *  4. 提供按地址、按区块号等查询区块的能力
 */




/**
 * 主网级 ContainerReader
 * 支持：
 *   - 解析 .que / .json 容器文件
 *   - 校验 tailHash
 *   - Bloom Filter 查询
 *   - 区块快速索引
 */

import com.alibaba.fastjson2.JSON;
import com.alibaba.fastjson2.JSONObject;
import org.que.core.queBlock.QueBaseBlock;
import org.que.crypto.CryptoUtil;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * 主网级 ContainerReader
 * 支持：
 *   - 解析 .que / .json 容器文件
 *   - 校验 tailHash
 *   - Bloom Filter 查询
 *   - 区块快速索引
 */
public class QueContainerReader {

    private QueContainerFileDTO dto;
    private String rawJson;
    private Path file;

    // ======= 读取并解析容器 =======
    public static QueContainerReader load(Path file) throws Exception {
        QueContainerReader reader = new QueContainerReader();

        reader.file = file;

        // 1) 读取完整 JSON
        reader.rawJson = Files.readString(file);

        // 2) 解析 DTO
        reader.dto = JSON.parseObject(reader.rawJson, QueContainerFileDTO.class);

        // 3) 校验 tailHash（唯一入口）
        if (!reader.verifyTailHash()) {
            throw new IllegalStateException("容器 tailHash 校验失败: " + file);
        }

        return reader;
    }

    /**
     * 生成“tailHash=null”后的 JSON，用于验证 tailHash 正确性
     */
    private String rawJsonWithoutTailHash() {
        JSONObject obj = JSON.parseObject(this.rawJson);
        // 非常重要：必须保留 tailHash 字段，但写 null，否则结构 hash 会改变
        obj.put("tailHash", null);
        return obj.toJSONString();
    }

    // =================== 基础信息 ===================

    public QueContainerHead getHead() { return dto.head; }
    public String getTailHash() { return dto.tailHash; }
    public List<QueContainerIndexEntry> getIndexList() { return dto.indexList; }
    public List<QueBaseBlock> getBlocks() { return dto.blocks; }
    public Path getFile() { return file; }

    // =================== tailHash 校验 ===================

    public boolean verifyTailHash() {
        String calc = CryptoUtil.sha3256Hex(
                rawJsonWithoutTailHash().getBytes(StandardCharsets.UTF_8)
        );
        return calc.equals(dto.tailHash);
    }

    // =================== Bloom Filter 查询 ===================

    public boolean mightContainAddress(String address) {
        for (QueContainerIndexEntry entry : dto.indexList) {
            if (entry.containsAddress(address)) {
                return true;
            }
        }
        return false;
    }

    // =================== 区块查找 ===================

    public QueBaseBlock findBlockByNumber(long blockNumber) {
        for (QueBaseBlock b : dto.blocks) {
            if (b.head.blockNumber == blockNumber) return b;
        }
        return null;
    }

    public QueBaseBlock findBlockByHash(String hash) {
        for (QueBaseBlock b : dto.blocks) {
            if (b.foot.blockHash.equals(hash)) return b;
        }
        return null;
    }

    public List<QueBaseBlock> findBlocksByAddress(String address) {
        List<QueBaseBlock> result = new ArrayList<>();
        if (!mightContainAddress(address)) return result;

        for (QueBaseBlock block : dto.blocks) {
            if (block.toJson().contains(address)) result.add(block);
        }
        return result;
    }

    public List<QueBaseBlock> getAllBlocks() {
        return dto.blocks;
    }
}

class QueContainerFileDTO {
    public QueContainerHead head;
    public List<QueContainerIndexEntry> indexList;
    public List<QueBaseBlock> blocks;
    public String tailHash;
}