package com.abc.spring.multithreading.thread;

import org.springframework.stereotype.Component;

@Component
public class MyRunnable implements Runnable {
    public void run() {
        System.out.println("Thread running :"+Thread.currentThread().getName());
    }
}
