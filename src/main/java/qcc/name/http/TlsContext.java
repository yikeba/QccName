package qcc.name.http;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedKeyManager;
import java.io.InputStream;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;
import java.security.KeyStore;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

/**
 * HTTPS 证书：从 keystore 文件（.jks 或 .p12 / .pfx）加载，JDK 自带，零依赖。
 * 证书热加载：HttpsServer 启动后不允许更换 HttpsConfigurator，所以 SSLContext 只创建一次，
 * 里面放一个"可替换的 KeyManager"；reloadIfChanged() 检测到文件修改时间变化就换掉内部的证书，
 * 之后的新握手立即使用新证书，已建立的连接不受影响 —— 续期后不用重启节点。
 */
public final class TlsContext {

    private final Path file;
    private final char[] pass;
    private final SwappableKeyManager km = new SwappableKeyManager();
    private FileTime loadedAt;
    private SSLContext ctx;

    public TlsContext(Path file, String pass) {
        this.file = file;
        this.pass = pass == null ? new char[0] : pass.toCharArray();
    }

    /** 首次加载并返回 SSLContext（只创建一次）。 */
    public synchronized SSLContext load() throws Exception {
        km.delegate = readKeyManager();
        if (ctx == null) {
            ctx = SSLContext.getInstance("TLS");
            ctx.init(new KeyManager[]{km}, null, null);
        }
        return ctx;
    }

    /** 证书文件变化则重新加载。返回是否换了证书；加载失败继续用旧证书。 */
    public synchronized boolean reloadIfChanged() {
        try {
            FileTime t = Files.getLastModifiedTime(file);
            if (t.equals(loadedAt)) return false;
            km.delegate = readKeyManager();
            return true;
        } catch (Exception e) {
            System.err.println("[https] 证书重新加载失败（继续使用旧证书）：" + e.getMessage());
            return false;
        }
    }

    private X509ExtendedKeyManager readKeyManager() throws Exception {
        FileTime t = Files.getLastModifiedTime(file);
        String n = file.getFileName().toString().toLowerCase();
        KeyStore ks = KeyStore.getInstance(n.endsWith(".jks") ? "JKS" : "PKCS12");
        try (InputStream in = Files.newInputStream(file)) { ks.load(in, pass); }
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(ks, pass);
        for (KeyManager m : kmf.getKeyManagers())
            if (m instanceof X509ExtendedKeyManager x) { loadedAt = t; return x; }
        throw new IllegalStateException("keystore 中没有可用的证书私钥");
    }

    /** 委托给当前证书的 KeyManager。 */
    private static final class SwappableKeyManager extends X509ExtendedKeyManager {
        volatile X509ExtendedKeyManager delegate;

        @Override public String[] getClientAliases(String t, Principal[] i) { return delegate.getClientAliases(t, i); }
        @Override public String chooseClientAlias(String[] t, Principal[] i, Socket s) { return delegate.chooseClientAlias(t, i, s); }
        @Override public String[] getServerAliases(String t, Principal[] i) { return delegate.getServerAliases(t, i); }
        @Override public String chooseServerAlias(String t, Principal[] i, Socket s) { return delegate.chooseServerAlias(t, i, s); }
        @Override public X509Certificate[] getCertificateChain(String a) { return delegate.getCertificateChain(a); }
        @Override public PrivateKey getPrivateKey(String a) { return delegate.getPrivateKey(a); }
        @Override public String chooseEngineClientAlias(String[] t, Principal[] i, SSLEngine e) { return delegate.chooseEngineClientAlias(t, i, e); }
        @Override public String chooseEngineServerAlias(String t, Principal[] i, SSLEngine e) { return delegate.chooseEngineServerAlias(t, i, e); }
    }
}