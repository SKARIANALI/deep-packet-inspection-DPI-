package dpi;

import java.util.Optional;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.TimeUnit;

public class ThreadSafeQueue<T> {
    private final ArrayBlockingQueue<T> queue;
    private volatile boolean shutdown;

    public ThreadSafeQueue(int maxSize) {
        this.queue = new ArrayBlockingQueue<>(maxSize);
    }

    public void push(T item) {
        try {
            while (!shutdown) {
                if (queue.offer(item, 100, TimeUnit.MILLISECONDS)) {
                    return;
                }
            }
        } catch (InterruptedException ignored) {
            Thread.currentThread().interrupt();
        }
    }

    public boolean tryPush(T item) {
        if (shutdown) {
            return false;
        }
        return queue.offer(item);
    }

    public Optional<T> pop() {
        try {
            T item = queue.take();
            return Optional.ofNullable(item);
        } catch (InterruptedException ignored) {
            Thread.currentThread().interrupt();
            return Optional.empty();
        }
    }

    public Optional<T> popWithTimeout(long timeoutMillis) {
        try {
            T item = queue.poll(timeoutMillis, TimeUnit.MILLISECONDS);
            return Optional.ofNullable(item);
        } catch (InterruptedException ignored) {
            Thread.currentThread().interrupt();
            return Optional.empty();
        }
    }

    public boolean isEmpty() {
        return queue.isEmpty();
    }

    public int size() {
        return queue.size();
    }

    public void shutdown() {
        shutdown = true;
    }

    public boolean isShutdown() {
        return shutdown;
    }
}
