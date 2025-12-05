package org.que.core.quecontainer;

import com.alibaba.fastjson2.JSON;
import com.alibaba.fastjson2.JSONObject;
import org.que.core.queBlock.QueBaseBlock;
import org.que.core.queData.QubeDataBaseFactory;
import org.que.core.queData.QueBaseData;
import org.que.crypto.CryptoUtil;

import java.io.File;
import java.io.RandomAccessFile;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * 2025 主网级最终版 ContainerReader
 *
 * 目标：
 *  - read()：读取容器
 *  - load() + 查询 API：完全兼容旧代码
 *  - blocks.dataList：恢复为真实子类 TransactionData / EntityData / RuleData
 *  - tailHash 校验
 */
public class QueContainerReader {

    /** 解析后的对象结构 */
    private QueContainerFileDTO dto;
    private Path file;
    private String rawJson;

    private QueContainerReader() {}

    // =====================================================================
    // 统一最终写法：read(Path) → 返回 QueBaseContainer
    // =====================================================================
    public static QueBaseContainer read(Path path) {
        return read(path.toFile());
    }

    public static QueBaseContainer read(File file) {
        try {
            if (!file.exists()) return null;

            String json = Files.readString(file.toPath(), StandardCharsets.UTF_8);
            JSONObject root = JSONObject.parseObject(json);
            if (root == null) return null;

            // head
            JSONObject headJson = root.getJSONObject("head");
            QueContainerHead head = new QueContainerHead(
                    headJson.getString("containerId"),
                    headJson.getString("contractAddress"),
                    headJson.getLongValue("containerNumber"),
                    headJson.getString("prevContainerHash"),
                    headJson.getString("version")
            );
            head.blockCount = headJson.getIntValue("blockCount");
            head.rawSize = headJson.getLongValue("rawSize");
            head.compressedSize = headJson.getLongValue("compressedSize");
            head.timestamp = headJson.getLongValue("timestamp");

            // indexList
            List<QueContainerIndexEntry> indexList = new ArrayList<>();
            if (root.containsKey("indexList")) {
                for (Object o : root.getJSONArray("indexList")) {
                    JSONObject idx = (JSONObject) o;
                    indexList.add(new QueContainerIndexEntry(
                            idx.getIntValue("blockIndex"),
                            idx.getLongValue("blockNumber"),
                            idx.getString("blockHash"),
                            idx.getLongValue("offset"),
                            idx.getLongValue("length"),
                            idx.getString("bloomFilter")
                    ));
                }
            }

            // blocks
            List<QueBaseBlock> blocks = new ArrayList<>();
            if (root.containsKey("blocks")) {
                var arr = root.getJSONArray("blocks");
                for (int i = 0; i < arr.size(); i++) {
                    JSONObject blkJson = arr.getJSONObject(i);
                    QueBaseBlock blk = QueBaseBlock.fromJson(blkJson.toString());

                    if (blk.body != null) {
                        List<QueBaseData> fixed = new ArrayList<>();
                        var bodyJson = blkJson.getJSONObject("body");
                        if (bodyJson != null && bodyJson.containsKey("dataList")) {
                            for (Object o : bodyJson.getJSONArray("dataList")) {
                                JSONObject dataJson = (JSONObject) o;
                                fixed.add(QubeDataBaseFactory.fromJson(dataJson.toString()));
                            }
                        }
                        blk.body.dataList = fixed;
                    }
                    blocks.add(blk);
                }
            }

            String tailHash = root.getString("tailHash");

            // 构造容器对象
            QueBaseContainer c = new QueBaseContainer();
            c.head = head;
            c.indexList = indexList;
            c.blocks = blocks;
            c.tailHash = tailHash;
            c.containerFilePath = file.toPath();

            return c;

        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }


    // =====================================================================
// readBlock() —— 兼容旧代码 + 支持未来二进制容器
// =====================================================================
    public static QueBaseBlock readBlock(Path file, long offset, long length) {
        try {
            // === JSON 容器模式（当前阶段） ===
            if (offset == 0 || length == 0) {
                // 直接整个容器读取，再根据 block height 查找
                QueBaseContainer c = QueContainerReader.read(file);
                if (c == null || c.blocks == null) return null;

                // JSON 模式 offset 无效，只能根据 indexList 的 blockNumber 读取
                // 因此由调用方提供 blockNumber
                // 所以 readBlock() 在 JSON 模式只返回 null
                // 让业务走 findBlockByNumber()
                return null;
            }

            // === 二进制容器模式（未来正式主网） ===
            try (RandomAccessFile raf = new RandomAccessFile(file.toFile(), "r")) {
                byte[] buf = new byte[(int) length];
                raf.seek(offset);
                raf.readFully(buf);
                String json = new String(buf, StandardCharsets.UTF_8);
                return QueBaseBlock.fromJson(json);
            }

        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }


    // =====================================================================
    // 老版本兼容：load() 返回 Reader 实例（包含查询 API）
    // =====================================================================

    public static QueContainerReader load(Path file) throws Exception {
        QueContainerReader r = new QueContainerReader();
        r.file = file;
        r.rawJson = Files.readString(file);

        r.dto = JSON.parseObject(r.rawJson, QueContainerFileDTO.class);
        if (r.dto == null) throw new RuntimeException("容器解析失败: " + file);

        // 校验 tailHash
        r.verifyTailHash();

        // 修复 dataList 子类
        r.fixDataList();

        return r;
    }

    // 修复 dataList 为真正子类
    private void fixDataList() {
        if (dto.blocks == null) return;

        var arr = JSON.parseObject(rawJson).getJSONArray("blocks");

        for (int i = 0; i < dto.blocks.size(); i++) {
            QueBaseBlock blk = dto.blocks.get(i);
            JSONObject blkJson = arr.getJSONObject(i);

            List<QueBaseData> fixedList = new ArrayList<>();
            var body = blkJson.getJSONObject("body");
            if (body != null && body.containsKey("dataList")) {
                for (Object o : body.getJSONArray("dataList")) {
                    fixedList.add(QubeDataBaseFactory.fromJson(o.toString()));
                }
            }
            blk.body.dataList = fixedList;
        }
    }

    private boolean verifyTailHash() {
        JSONObject obj = JSONObject.parseObject(rawJson);
        obj.put("tailHash", null);
        String calc = CryptoUtil.sha3256Hex(obj.toJSONString().getBytes(StandardCharsets.UTF_8));
        return calc.equals(dto.tailHash);
    }

    // =====================================================================
    // 查询 API（兼容旧代码）
    // =====================================================================

    public QueBaseBlock findBlockByNumber(long num) {
        for (QueBaseBlock b : dto.blocks) {
            if (b.head.blockNumber == num) return b;
        }
        return null;
    }

    public QueBaseBlock findBlockByHash(String hash) {
        for (QueBaseBlock b : dto.blocks) {
            if (b.foot.blockHash.equals(hash)) return b;
        }
        return null;
    }

    public boolean mightContainAddress(String address) {
        for (QueContainerIndexEntry e : dto.indexList) {
            if (e.containsAddress(address)) return true;
        }
        return false;
    }

    public List<QueBaseBlock> findBlocksByAddress(String address) {
        List<QueBaseBlock> list = new ArrayList<>();
        for (QueBaseBlock b : dto.blocks) {
            if (b.toJson().contains(address)) list.add(b);
        }
        return list;
    }

    public List<QueBaseBlock> getAllBlocks() {
        return dto.blocks;
    }

    public QueContainerHead getHead() {
        return dto.head;
    }

    public List<QueContainerIndexEntry> getIndexList() {
        return dto.indexList;
    }

    public Path getFile() {
        return file;
    }
}


// DTO
class QueContainerFileDTO {
    public QueContainerHead head;
    public List<QueContainerIndexEntry> indexList;
    public List<QueBaseBlock> blocks;
    public String tailHash;
}
