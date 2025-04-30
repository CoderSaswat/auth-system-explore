package com.abc.spring.multithreading.controller;

import com.abc.spring.multithreading.entity.FoodOrder;
import com.abc.spring.multithreading.entity.Order;
import com.abc.spring.multithreading.service.TestService;
import com.abc.spring.multithreading.thread.ExecutorServiceExample;
import com.abc.spring.multithreading.thread.MyThread;
import org.springframework.web.bind.annotation.*;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;

@RestController
@RequestMapping("/test")
public class TestController {
    private final TestService testService;

    public TestController(TestService testService, ExecutorServiceExample executorServiceExample) {
        this.testService = testService;
    }

    @GetMapping
    public void test() throws InterruptedException, ExecutionException {
        testService.test();
    }

    @PostMapping
    public String placeOrder(@RequestBody FoodOrder order) throws InterruptedException {
//        return testService.placeOrder(order);
//        return testService.placeFoodOrder(order);
//        testService.startEvenOddPrintig();
        testService.produceConsume();
        return "";
    }
}
