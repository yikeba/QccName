package qcc.name.core;

/** 一个已注册名称的状态。regSeq = 注册帧的 seq，删除签名必须指明它。 */
public record NameRecord(String address, String credentialHash, long regSeq, long regTime) {}
