package com.abc.spring.multithreading.thread;

import org.springframework.stereotype.Service;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

@Service
public class ExecutorServiceExample {
    private final ExecutorService executorService = Executors.newFixedThreadPool(5); // Pool with 5 threads

    public void executeTask() {
        executorService.submit(() -> {
            try {
                Thread.sleep(2000);
            } catch (InterruptedException e) {
                throw new RuntimeException(e);
            }
            System.out.println("Thread executing, Thread name : " + Thread.currentThread().getName());
        });
    }
}
