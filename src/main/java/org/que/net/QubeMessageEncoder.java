package org.que.net;


import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.MessageToByteEncoder;

/**
 * Netty 编码器：将 QubeMessage 对象编码为字节流。
 */
public class QubeMessageEncoder extends MessageToByteEncoder<QubeMessage> {

    @Override
    protected void encode(ChannelHandlerContext ctx, QubeMessage msg, ByteBuf out) {
        // 1. Magic Number (4 Bytes)
        out.writeInt(QubeMessage.MAGIC_NUMBER);

        // 2. Version (1 Byte)
        out.writeByte(QubeMessage.VERSION);

        // 3. MessageType (1 Byte)
        out.writeByte(msg.getType().getCode());

        // 4. DataLength (4 Bytes)
        // 注意：数据体不能为 null
        int dataLength = (msg.getData() == null) ? 0 : msg.getData().length;
        out.writeInt(dataLength);

        // 5. Data (Value) (Variable Bytes)
        if (dataLength > 0) {
            out.writeBytes(msg.getData());
        }
    }
}