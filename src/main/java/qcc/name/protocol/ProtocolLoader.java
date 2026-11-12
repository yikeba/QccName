package qcc.name.protocol;

import qcc.name.codec.Sha3;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Map;

/**
 * 引导协议加载器。信任根只有两个硬编码常量：protocolTxHash（去哪儿取）与
 * protocolHash（取到的是不是那一份）。不询问"最新版本"，取到的字节 hash 不符即拒绝启动。
 *
 * 链上取回的格式（GET /v1/hash/{txHash}，已实测）：
 *   {"ok":true,"data":"{\"tx\":\"{...\\\"payload\\\":[123,10,...,-26,-100,...]}\"..."}
 *   data 与 tx 都是被转义的 JSON 字符串，要逐层再解析；
 *   payload 是 **Java 有符号字节数组**，中文 UTF-8 字节为负数，必须按 x & 0xFF 还原。
 */
public final class ProtocolLoader {

    /**
     * qcc-name v1.0.0 的链上定位。
     * 【未上链】发布后把交易 hash 与协议 hash 填进来，此后 loadFromChain 才可用；
     * 本地调试走 loadFile(path, null)，会打印实际 hash 供核对。
     */
    public static final String PROTOCOL_TX_HASH = "";
    public static final String PROTOCOL_HASH    = "";

    private ProtocolLoader() {}

    /** 校验 hash 后解析。expectedHash 为 null 仅用于本地调试（未上链前）。 */
    public static NameProtocol load(byte[] raw, String expectedHash) {
        String actual = Sha3.toHex(Sha3.hash(raw));
        if (expectedHash != null && !actual.equals(expectedHash))
            throw new IllegalStateException("[ProtocolLoader] 协议 hash 不符：期望 " + expectedHash
                    + " 实际 " + actual + " —— 拒绝启动");
        return NameProtocol.parse(raw);
    }

    public static NameProtocol loadFile(Path file, String expectedHash) {
        try {
            return load(Files.readAllBytes(file), expectedHash);
        } catch (java.io.IOException e) {
            throw new IllegalStateException("[ProtocolLoader] 读取失败: " + file, e);
        }
    }

    /** 从 QCC 链取回并校验。 */
    public static NameProtocol loadFromChain(String chainBaseUrl) {
        if (PROTOCOL_TX_HASH.isEmpty() || PROTOCOL_HASH.isEmpty())
            throw new IllegalStateException("[ProtocolLoader] qcc-name v1.0.0 尚未上链，常量未填写");
        return load(fetchPayload(chainBaseUrl, PROTOCOL_TX_HASH), PROTOCOL_HASH);
    }

    /** 取一笔 QCCData 交易的原始 payload 字节。 */
    public static byte[] fetchPayload(String chainBaseUrl, String txHash) {
        try {
            HttpClient c = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build();
            HttpRequest req = HttpRequest.newBuilder(URI.create(chainBaseUrl + "/v1/hash/" + txHash))
                    .timeout(Duration.ofSeconds(20)).GET().build();
            HttpResponse<byte[]> r = c.send(req, HttpResponse.BodyHandlers.ofByteArray());
            if (r.statusCode() != 200) throw new IllegalStateException("HTTP " + r.statusCode());
            return payloadFromTxResponse(r.body());
        } catch (Exception e) {
            throw new IllegalStateException("[ProtocolLoader] 链上取回失败: " + txHash, e);
        }
    }

    /** 解析 /v1/hash 响应，还原 payload 原始字节。 */
    public static byte[] payloadFromTxResponse(byte[] body) {
        try {
            return qcc.name.chain.ChainTx.parse(null, body).payload();
        } catch (IllegalArgumentException e) {
            throw new IllegalStateException(e.getMessage(), e);
        }
    }

    /**
     * 确定保留名发布者：向多个链节点取回 protocolTx（ChainView.tx 要求一致确认），
     * payload 的 SHA3-256 必须等于本地协议 hash、chain 必须一致；交易 from 即发布者。
     * 链暂时不可达时每 10 秒重试（发布者参与 genesisExecHash，确定不了就不能启动）。
     */
    public static NameProtocol withPublisherFromChain(NameProtocol p, qcc.name.chain.ChainView chain, String protocolTx) {
        for (int attempt = 1; ; attempt++) {
            try {
                qcc.name.chain.ChainTx tx = chain.tx(protocolTx);
                if (tx == null) throw new IllegalStateException("[ProtocolLoader] 链上查不到 protocolTx " + protocolTx);
                if (!tx.payloadHash().equals(p.protocolHash))
                    throw new IllegalStateException("[ProtocolLoader] protocolTx 的 payload hash " + tx.payloadHash()
                            + " 与本地协议文件 " + p.protocolHash + " 不同 —— 拒绝启动");
                if (!tx.chain().equals(p.chain))
                    throw new IllegalStateException("[ProtocolLoader] protocolTx 的 chain=" + tx.chain() + " 与协议 chain=" + p.chain + " 不同");
                System.out.println("  协议交易 " + protocolTx.substring(0, 16) + "… 高度 " + tx.height() + "  发布者 " + tx.from());
                return p.withReservedPublisher(tx.from());
            } catch (qcc.name.chain.ChainUnavailableException e) {
                System.err.println("[ProtocolLoader] 取回 protocolTx 失败（第 " + attempt + " 次，10 秒后重试）：" + e.getMessage());
                try { Thread.sleep(10_000); } catch (InterruptedException ie) { Thread.currentThread().interrupt(); throw new IllegalStateException("启动被中断"); }
            }
        }
    }
}
