package org.que.api;

import org.que.core.cache.MemoryBalanceServer;

public class BalanceQueryAPI {

    private final MemoryBalanceServer balanceServer;

    public BalanceQueryAPI(MemoryBalanceServer server) {
        this.balanceServer = server;
    }

    public long getBalance(String address) {
        return balanceServer.getBalance(address);
    }
}

