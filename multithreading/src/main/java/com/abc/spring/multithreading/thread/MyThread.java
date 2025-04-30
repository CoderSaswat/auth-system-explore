package com.abc.spring.multithreading.thread;

import org.springframework.stereotype.Component;

@Component
public class MyThread extends Thread {
    @Override
    public void run() {
        System.out.println("thread running "+Thread.currentThread().getName());
    }
}
