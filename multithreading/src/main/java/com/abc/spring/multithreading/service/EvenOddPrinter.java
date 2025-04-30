package com.abc.spring.multithreading.service;

import org.springframework.stereotype.Component;

@Component
public class EvenOddPrinter {
    private Integer number = 1;

    public synchronized void printEven() throws InterruptedException {
        while (number <= 100){
            if(number % 2 ==0){
                System.out.println(Thread.currentThread().getName()+": even number :"+number);
                number++;
                notify();
            }else{
                wait();
            }
        }
    }

    public synchronized void printOdd() throws InterruptedException {
        while (number<=100){
            if(number % 2 !=0){
                System.out.println(Thread.currentThread().getName()+" :odd number :"+number);
                number++;
                notify();
            }else{
                wait();
            }
        }
    }
}
