package com.abc.spring.multithreading.service;

import com.abc.spring.multithreading.entity.FoodOrder;
import com.abc.spring.multithreading.entity.Order;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;

public interface TestService {
    void test() throws InterruptedException, ExecutionException;
    CompletableFuture<String> placeOrder(Order order);
    CompletableFuture<String> placeFoodOrder(FoodOrder order);

    void startEvenOddPrintig();

    void produceConsume();
}
