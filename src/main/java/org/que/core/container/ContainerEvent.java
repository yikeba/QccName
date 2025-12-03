package org.que.core.container;


import org.que.core.quecontainer.QueBaseContainer;

public class ContainerEvent {

    public final ContainerEventType type;
    public final QueBaseContainer container;

    public ContainerEvent(ContainerEventType type, QueBaseContainer container) {
        this.type = type;
        this.container = container;
    }

    @Override
    public String toString() {
        return "ContainerEvent{" +
                "type=" + type +
                ", container=" + container +
                '}';
    }
}
