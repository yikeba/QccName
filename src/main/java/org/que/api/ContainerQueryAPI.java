package org.que.api;

import org.que.config.QubePath;
import org.que.core.queBlock.QueBaseBlock;
import org.que.core.quecontainer.QueBaseContainer;
import org.que.core.quecontainer.QueContainerReader;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

public class ContainerQueryAPI {

    public List<QueBaseContainer> listAllContainers() throws Exception {
        List<QueBaseContainer> result = new ArrayList<>();

        try (var stream = Files.list(QubePath.CONTAINER_DIR)) {
            for (Path p : stream.toList()) {
                if (!p.toString().endsWith(".que")) continue;
                try {
                    QueBaseContainer c  = QueContainerReader.read(p.toFile());
                    result.add(c);
                } catch (Exception ignored) {}
            }
        }
        return result;
    }

    public QueBaseBlock findBlock(long blockNumber) throws Exception {
        try (var stream = Files.list(QubePath.CONTAINER_DIR)) {
            for (Path p : stream.toList()) {
                QueContainerReader reader = QueContainerReader.load(p);
                QueBaseBlock b = reader.findBlockByNumber(blockNumber);
                if (b != null) return b;
            }
        }
        return null;
    }
}
