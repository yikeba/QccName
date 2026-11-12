package qcc.name.state;

import qcc.name.core.*;
import qcc.name.codec.*;
import java.nio.file.*; import java.util.*;
/**
 * state + core 层一致性向量 —— 第二批。
 *
 * 与 CodecSelfTest 一样,这些断言定义"什么叫兼容实现",
 * 而不只是测试本实现有没有 bug。重点覆盖三类:
 *   1. 持久性与崩溃恢复(重启、尾部残记录、段间隙)
 *   2. 确定性(编码与 emit 顺序无关、flatRoot 与 apply 顺序无关)
 *   3. 不变量强制(owner 必须已绑定、不能删不存在的记录、冲突 delta 被拒)
 *
 * 运行: java -Dstdout.encoding=UTF-8 -cp <out> qcc.name.state.StateSelfTest
 */
public class StateSelfTest {
  static int failed=0;
  static void ck(boolean c,String m){ if(!c) failed++; System.out.println((c?"  OK   ":"  FAIL ")+m); }
  static boolean thr(Runnable r){ try{r.run();return false;}catch(Exception e){return true;} }
  static String nh(String s){ return Sha3.hashUtf8Hex(s); }

  public static void main(String[] a) throws Exception {
    Path dir = Files.createTempDirectory("oplog");

    // ---- OpLogStore ----
    OpLogStore log = new OpLogStore(dir);
    ck(log.isEmpty() && log.maxSeq()==0, "空日志初始状态");
    for(int i=1;i<=1000;i++) log.append(("op-"+i).getBytes());
    log.sync();
    ck(log.maxSeq()==1000, "追加 1000 条,seq 连续到 1000");
    ck(new String(log.read(1)).equals("op-1") && new String(log.read(1000)).equals("op-1000"), "首尾随机读正确");
    ck(log.read(0)==null && log.read(1001)==null, "越界 seq 返回 null");
    byte[] h1 = log.seqHash(1,1000);
    log.close();

    OpLogStore log2 = new OpLogStore(dir);              // 重启重建索引
    ck(log2.maxSeq()==1000, "重启后 maxSeq 恢复");
    ck(Arrays.equals(h1, log2.seqHash(1,1000)), "重启后 seqHash 一致");
    ck(new String(log2.read(500)).equals("op-500"), "重启后随机读正确");
    log2.close();

    // 崩溃残留:尾部截断一半
    Path seg = dir.resolve("oplog_0.qlog");
    long sz = Files.size(seg);
    try(var ch=java.nio.channels.FileChannel.open(seg, StandardOpenOption.WRITE)){ ch.truncate(sz-5); }
    OpLogStore log3 = new OpLogStore(dir);
    ck(log3.maxSeq()==999, "尾部残记录被截断,maxSeq 回退到 999");
    long next = log3.append("recovered".getBytes());
    ck(next==1000, "截断后可继续追加,seq 复用 1000");
    log3.close();

    // 段间隙检测
    Path gapDir = Files.createTempDirectory("gap");
    Files.copy(seg, gapDir.resolve("oplog_0.qlog"));
    Files.copy(seg, gapDir.resolve("oplog_2.qlog"));
    ck(thr(()->new OpLogStore(gapDir)), "段序号不连续时拒绝启动");

    // ---- ForwardRecord ----
    ForwardRecord r = new ForwardRecord(List.of("addrA"), "addrA", 1, 1);
    ck(Arrays.equals(r.encode(), ForwardRecord.decode(r.encode()).encode()), "ForwardRecord 编码往返");
    ck(thr(()->new ForwardRecord(List.of("x"),"y",1,1)), "owner 不在 addresses 中被拒绝");
    ck(thr(()->new ForwardRecord(List.of(),"y",1,1)), "空 addresses 被拒绝");
    ForwardRecord r2 = r.withAddressAdded("addrB", 2);
    ck(r.addresses.size()==1 && r2.addresses.size()==2, "不可变:原实例未被修改");
    ck(thr(()->r2.withAddressRemoved("addrA",3)), "不能解绑 owner");

    // ---- StateDelta 顺序无关性 ----
    String n1=nh("alice"), n2=nh("bob");
    StateDelta d1 = StateDelta.builder().putForward(n1,r).putReverse("addrA",n1).putForward(n2,r).build();
    StateDelta d2 = StateDelta.builder().putForward(n2,r).putReverse("addrA",n1).putForward(n1,r).build();
    ck(Arrays.equals(d1.encode(), d2.encode()), "StateDelta 编码与 emit 顺序无关");
    ck(Arrays.equals(d1.encode(), StateDelta.decode(d1.encode()).encode()), "StateDelta 往返");
    ck(thr(()->StateDelta.builder().putForward(n1,r).delForward(n1).build()), "同 key 既 PUT 又 DEL 被拒绝");
    ck(thr(()->StateDelta.builder().putForward(n1,r).putForward(n1,r).build()), "重复变更被拒绝");
    ck(StateDelta.empty().isEmpty(), "空 delta");

    // ---- NameState ----
    NameState s1 = new NameState();
    s1.apply(StateDelta.builder().putForward(n1,r).putReverse("addrA",n1).build());
    ck(s1.nameTaken(n1) && s1.addressTaken("addrA"), "注册后正反向都存在");
    ck(s1.nextIncarnation(n1)==1 && s1.nextIncarnation(nh("nobody"))==1, "未释放过的名字世代号为 1");

    // 同样的变更,不同 apply 顺序 → 相同 flatRoot
    NameState s2 = new NameState();
    s2.apply(StateDelta.builder().putReverse("addrA",n1).putForward(n1,r).build());
    ck(s1.flatRootHex().equals(s2.flatRootHex()), "flatRoot 与 apply 顺序无关");

    // 释放 + 世代号
    s1.apply(StateDelta.builder().delForward(n1).delReverse("addrA")
             .putTombstone(n1, new Tombstone(2, 342665, 3)).build());
    ck(!s1.nameTaken(n1) && s1.nextIncarnation(n1)==2, "释放后名字可用,世代号进位到 2");
    Tombstone t = s1.tombstone(n1);
    ck(!t.cooldownPassed(342665+100, 259200) && t.cooldownPassed(342665+259200, 259200), "冷却期按区块高度判定");
    ck(thr(()->s1.apply(StateDelta.builder().delForward(n1).build())), "删不存在的记录被拒绝");

    System.out.println();
    System.out.println(failed==0 ? "全部通过" : failed+" 项失败");
    if(failed!=0) System.exit(1);
  }
}
