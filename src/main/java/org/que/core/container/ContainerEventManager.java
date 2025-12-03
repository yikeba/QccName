package org.que.core.container;


import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * 容器生命周期事件系统（事件总线）
 */
public class ContainerEventManager {

    private static final List<ContainerEventListener> listeners = new CopyOnWriteArrayList<>();

    // 注册监听器（在系统启动时注册）
    public static void register(ContainerEventListener listener) {
        if (listener != null) {
            listeners.add(listener);
        }
    }

    // 触发事件（容器写入、冷链完成、余额重算等）
    public static void trigger(ContainerEvent event) {
        if (event == null) return;

        for (ContainerEventListener listener : listeners) {
            try {
                listener.onEvent(event);
            } catch (Throwable t) {
                // 确保单个监听器不会影响整体链路
                t.printStackTrace();
            }
        }
    }
}
