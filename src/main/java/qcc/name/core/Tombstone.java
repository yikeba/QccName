package qcc.name.core;

/** 名称删除/回收记录：releasedTime 起算冷却期，期内任何人（含原地址）不得注册。 */
public record Tombstone(long releasedTime, long regSeq) {}
