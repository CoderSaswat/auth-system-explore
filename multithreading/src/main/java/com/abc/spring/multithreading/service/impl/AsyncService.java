package com.abc.spring.multithreading.service.impl;

import com.abc.spring.multithreading.entity.FoodOrder;
import com.abc.spring.multithreading.entity.Order;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;

@Service
public class AsyncService {
    @Async
    public void async1() throws InterruptedException {
        Thread.sleep(5000);
        System.out.println(Thread.currentThread().getName());
        System.out.println("async1");
    }

    @Async
    public void async2() throws InterruptedException {
        Thread.sleep(5000);
        System.out.println(Thread.currentThread().getName());
        System.out.println("async2");
    }

    @Async
    public CompletableFuture<List<Integer>> produceNos() throws InterruptedException {
        List<Integer> list = new ArrayList<>();
        for (int i = 1; i <= 10; i++) {
            list.add(i);
        }
        Thread.sleep(2000);
        return CompletableFuture.completedFuture(list);
    }

    @Async
    public CompletableFuture<Boolean> sendOrderConfirmation(String email, Long orderId) {
        try {
            Thread.sleep(2000); // Simulating email delay
            boolean success = Math.random() > 0.3; // 70% chance of success
            System.out.println("Email " + (success ? "Sent" : "Failed") + " to " + email + " for Order ID: " + orderId);
            return CompletableFuture.completedFuture(success);
        } catch (InterruptedException e) {
            return CompletableFuture.completedFuture(false);
        }
    }

    @Async
    public CompletableFuture<Boolean> processPayment(Order order) {
        try {
            Thread.sleep(3000); // Simulating payment processing delay
            boolean success = Math.random() > 0.2; // 80% chance of success
            System.out.println("Payment " + (success ? "Successful" : "Failed") + " for Order: " + order.getId());
            return CompletableFuture.completedFuture(success);
        } catch (InterruptedException e) {
            return CompletableFuture.completedFuture(false);
        }
    }

    @Async
    public CompletableFuture<Boolean> processPayment(FoodOrder order) {
        try {
            Thread.sleep(3000); // Simulating payment processing delay
            boolean success = Math.random() > 0.2; // 80% chance of success
            System.out.println("Payment " + (success ? "Successful" : "Failed") + " for Order: " + order.getId());
            return CompletableFuture.completedFuture(success);
        } catch (InterruptedException e) {
            return CompletableFuture.completedFuture(false);
        }
    }

    @Async
    public CompletableFuture<Boolean> notifyRestaurant(FoodOrder order) {
        try {
            Thread.sleep(2000); // Simulating notification delay
            boolean success = Math.random() > 0.2; // 80% chance of success

            if (success) {
                System.out.println("✅ Restaurant Notified for Order ID: " + order.getId());
            } else {
                System.out.println("❌ Restaurant Notification Failed for Order ID: " + order.getId());
            }

            return CompletableFuture.completedFuture(success);
        } catch (InterruptedException e) {
            return CompletableFuture.completedFuture(false);
        }
    }

    @Async
    public CompletableFuture<Boolean> assignRider(FoodOrder order) {
        try {
            Thread.sleep(3000); // Simulating delay in assigning a rider
            boolean success = Math.random() > 0.3; // 70% chance of success

            if (success) {
                System.out.println("✅ Rider Assigned for Order ID: " + order.getId());
            } else {
                System.out.println("❌ No Rider Available for Order ID: " + order.getId());
            }

            return CompletableFuture.completedFuture(success);
        } catch (InterruptedException e) {
            return CompletableFuture.completedFuture(false);
        }
    }
}

