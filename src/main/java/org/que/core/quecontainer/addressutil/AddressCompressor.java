package org.que.core.quecontainer.addressutil;

import net.jpountz.lz4.LZ4Compressor;
import net.jpountz.lz4.LZ4Factory;
import org.bouncycastle.util.encoders.Hex;

import java.io.ByteArrayOutputStream;
import java.util.Arrays;
import java.util.Set;

public class AddressCompressor {

    public static byte[] compressHash160List(Set<String> h160List) {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        // 写入数量（最多255）
        baos.write(h160List.size());
        // 写入每个 hash160 的 20 字节
        for (String hex : h160List) {
            byte[] h = Hex.decode(hex);
            baos.write(h, 0, 20);
        }

        byte[] origin = baos.toByteArray();

        // LZ4
        LZ4Factory factory = LZ4Factory.fastestInstance();
        LZ4Compressor compressor = factory.fastCompressor();

        int maxLen = compressor.maxCompressedLength(origin.length);
        byte[] compressed = new byte[maxLen];

        int size = compressor.compress(
                origin, 0, origin.length,
                compressed, 0, maxLen
        );

        return Arrays.copyOf(compressed, size);
    }
}
