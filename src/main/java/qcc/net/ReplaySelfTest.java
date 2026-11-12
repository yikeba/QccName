package qcc.name.verify;

import qcc.name.chain.*;
import qcc.name.codec.*;
import qcc.name.core.*;
import qcc.name.protocol.*;
import qcc.name.state.*;
import java.nio.file.*; import java.util.*;
/**
 * 端到端独立验证向量 —— 第五批。
 *
 * 这一批把前四批串起来:链上协议 → 写日志 → 离线重放 → 比对 → 出证明。
 * 最要紧的三条:
 *   - 篡改文件中部被拒绝启动(而不是静默截断后半段历史)
 *   - 分歧精确定位到具体 seq(逐条推进 execHash 换来的能力)
 *   - 165 字节的证明让用户自证归属,不需要信任任何节点
 *
 * 运行: java -Dstdout.encoding=UTF-8 -cp <out> qcc.name.verify.ReplaySelfTest [协议文件]
 */
public class ReplaySelfTest {
  static int failed=0;
  static void ck(boolean c,String m){ if(!c) failed++; System.out.println((c?"  OK   ":"  FAIL ")+m); }
  static final String CRED="7ee5f7b3543fae3e68c59599bdc9134e7637bcbcc6f9f538a980bc200fe39598";
  static final String TAG="qccname";
  static final String INST="a9cabae245a9595bd937775e7441a632d8de518fad6fb404a097a8b745dafde7";
  static final long H0=342665L, H=H0+10;
  static final String A="QaddrAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", B="QaddrBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";

  public static void main(String[] x) throws Exception {
    byte[] doc=Files.readAllBytes(Path.of(x.length>0?x[0]:"qcc-name-v1.json"));
    ProtocolRoot root=ProtocolLoader.loadFromBytes(doc, ProtocolLoader.PROTOCOL_HASH);

    // 录制的链上事实:A/B 都有 100 QCC 质押到 qccos
    Map<String,PledgeFact> f=new TreeMap<>();
    PledgeFact good=new PledgeFact(true,"QCC",30_000_000_000L);   // 链上实测值:30 QCC
    f.put(RecordedChainView.key(A,TAG,CRED), good);
    f.put(RecordedChainView.key(B,TAG,CRED), good);
    RecordedChainView chain=new RecordedChainView(f, Map.of(), H);

    // 事实录落盘再载入 —— 验证者拿到的就是这个文件
    Path fp=Files.createTempFile("facts",".bin"); chain.save(fp);
    RecordedChainView loaded=RecordedChainView.load(fp);
    ck(loaded.authPledge(A,TAG,CRED).amount()==30_000_000_000L, "事实录落盘/载入往返");

    // 写一段真实日志
    Path dir=Files.createTempDirectory("replay");
    OpLogStore log=new OpLogStore(dir);
    append(log,1,OpHandlers.registerPayload("alice",A,CRED),List.of(A));   // OK
    append(log,1,OpHandlers.registerPayload("alice",B,CRED),List.of(B));   // nameTaken
    append(log,1,OpHandlers.registerPayload("bob",  B,CRED),List.of(B));   // OK
    append(log,2,OpHandlers.nameAndAddr("alice",B),List.of(A,B));          // addressTaken
    append(log,4,OpHandlers.nameAndAddr("alice",A),List.of(A));            // transferOwner->A(自己)
    log.sync();
    ck(log.maxSeq()==5, "日志写入 5 条");

    // ── 重放 ──
    Replayer rp=new Replayer(root,INST,H0,TAG,loaded,Replayer.SignatureVerifier.SKIP);
    VerifyReport r1=rp.replay(log);
    ck(r1.steps().size()==5, "重放 5 步");
    ck(r1.steps().get(0).resultCode()==0,  "seq1 register alice → OK");
    ck(r1.steps().get(1).resultCode()==12, "seq2 重复 → nameTaken");
    ck(r1.steps().get(2).resultCode()==0,  "seq3 register bob → OK");
    ck(r1.steps().get(3).resultCode()==20, "seq4 → addressTaken");
    ck(r1.rejectedCount()==2, "被拒 2 条");

    // 两次重放一致
    VerifyReport r2=rp.replay(log);
    ck(r1.finalExecHash().equals(r2.finalExecHash()), "两次重放 execHash 一致");
    ck(r1.merkleStateRoot().equals(r2.merkleStateRoot()), "两次重放 stateRoot 一致");

    // 与锚定值比对:通过
    VerifyReport ok=rp.replay(log,1,log.maxSeq(),r1.finalExecHash());
    ck(ok.ok(), "与锚定 execHash 一致 → 通过");

    // 与错误锚定值比对:不通过
    VerifyReport bad=rp.replay(log,1,log.maxSeq(),Sha3.hashUtf8Hex("wrong"));
    ck(!bad.ok(), "与错误锚定值比对 → 不通过");

    // ── 篡改检测 ──
    Path dir2=Files.createTempDirectory("tamper");
    for(Path p:Files.list(dir).toList()) Files.copy(p,dir2.resolve(p.getFileName()));
    OpLogStore t=new OpLogStore(dir2);
    // 把 seq3 的 bob 改成 carol —— 等长替换,CRC 会重算不了,所以直接改字节看能否被发现
    Path seg=dir2.resolve("oplog_0.qlog");
    byte[] raw=Files.readAllBytes(seg);
    int idx=indexOf(raw,"bob".getBytes());
    ck(idx>0,"定位到日志里的明文 name(说明 name 确实以明文入日志,验证者可独立复算 nameHash)");
    raw[idx]='c'; raw[idx+1]='a'; raw[idx+2]='t';
    Files.write(seg,raw);
    boolean caught=false; String why="";
    try{ OpLogStore t2=new OpLogStore(dir2); }
    catch(Exception e){ caught=true; why=e.getMessage()==null?"":e.getMessage(); }
    ck(caught && why.contains("篡改"), "篡改文件中部 → 拒绝启动(不静默截断后半段历史)");

    // ── 分歧定位 ──
    List<VerifyReport.Step> anchored=new ArrayList<>(r1.steps());
    anchored.set(3,new VerifyReport.Step(4,2,20,Sha3.hashUtf8Hex("divergent")));
    long at=rp.locateDivergence(r1,anchored);
    ck(at==4, "分歧精确定位到 seq=4(不是'某个批次里有问题')");

    // ── Merkle 证明:用户自证归属 ──
    NameStateMachine sm=new NameStateMachine(root,root.genesisExecHash(INST,H0));
    replayInto(sm,log,loaded);
    byte[] mroot=Replayer.merkleRoot(sm.state());
    String aliceHash=NameValidator.nameHash("alice");
    byte[] lk=NameState.leafKey(StateDelta.PUT_FORWARD,aliceHash);
    MerkleProof pf=Replayer.prove(sm.state(),lk);
    byte[] lv=NameState.leafValue(StateDelta.PUT_FORWARD,aliceHash,sm.state().forward(aliceHash).encode());
    ck(pf.provesPresence()&&pf.verify(mroot,lv), "alice 的包含证明可验("+pf.sizeBytes()+" 字节)");

    byte[] gk=NameState.leafKey(StateDelta.PUT_FORWARD,NameValidator.nameHash("nobody"));
    MerkleProof pg=Replayer.prove(sm.state(),gk);
    ck(pg.provesAbsence()&&pg.verify(mroot,null), "nobody 的不存在证明可验("+pg.sizeBytes()+" 字节)");

    System.out.println();
    System.out.println(r1.print());
    System.out.println();
    System.out.println(failed==0?"全部通过":failed+" 项失败");
    if(failed!=0) System.exit(1);
  }

  static long seq=0;
  static void append(OpLogStore log,int code,byte[] payload,List<String> signers){
    OpInput in=new OpInput(code,H,H,payload,signers,Sha3.hashUtf8("sig"),true,++seq,PledgeFact.none());
    log.append(in.encodeForLog());
  }
  static void replayInto(NameStateMachine sm,OpLogStore log,ChainView cv){
    for(long s=1;s<=log.maxSeq();s++){
      OpInput probe=OpInput.decodeFromLog(log.read(s),true,s,PledgeFact.none());
      PledgeFact pf=PledgeFact.none();
      if(probe.opCode==1){
        var r=new QccCanonicalReader(probe.payload); r.str();
        pf=cv.authPledge(r.str(),TAG,r.hash32Hex());
      }
      sm.apply(OpInput.decodeFromLog(log.read(s),true,s,pf));
    }
  }
  static int indexOf(byte[] a,byte[] n){
    outer: for(int i=0;i<=a.length-n.length;i++){
      for(int j=0;j<n.length;j++) if(a[i+j]!=n[j]) continue outer;
      return i;
    } return -1;
  }
}
