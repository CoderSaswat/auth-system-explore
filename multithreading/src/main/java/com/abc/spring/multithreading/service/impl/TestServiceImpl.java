package com.abc.spring.multithreading.service.impl;

import com.abc.spring.multithreading.entity.FoodOrder;
import com.abc.spring.multithreading.entity.Order;
import com.abc.spring.multithreading.service.EvenOddPrinter;
import com.abc.spring.multithreading.service.TestService;
import com.abc.spring.multithreading.thread.ExecutorServiceExample;
import com.abc.spring.multithreading.thread.MyRunnable;
import com.abc.spring.multithreading.thread.MyThread;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.concurrent.*;

@Service
public class TestServiceImpl implements TestService {

    private final MyThread myThread;
    private final MyRunnable myRunnable;
    private final ExecutorServiceExample executorServiceExample;
    private final AsyncService asyncService;


    public TestServiceImpl(MyThread myThread, MyRunnable myRunnable, ExecutorServiceExample executorServiceExample, AsyncService asyncService) {
        this.myThread = myThread;
        this.myRunnable = myRunnable;
        this.executorServiceExample = executorServiceExample;
        this.asyncService = asyncService;
    }


    public void test() throws InterruptedException, ExecutionException {
//        myThread.start();
//        myRunnable.run();
//        executorServiceExample.executeTask();
        //not working withing this class
//        async1();
//        async2();

        //working if we have a separate async class
//        asyncService.async1();
//        asyncService.async2();

        CompletableFuture<List<Integer>> futureResults = asyncService.produceNos();
        // Perform other operations while async task is running
        System.out.println("Doing some other work in main thread...");

        // Get the result when it's ready
        //blocking
//        System.out.println("Async Result: " + futureResults.get());

        //non-blocking
//        futureResults.thenAccept(result -> System.out.println("Async Result: " + result));
        //non-blocking

//        futureResults.thenApply(result -> {
//            System.out.println("Async Result: " + result);
//            return result;
//        });

        System.out.println("Doing some other work in main thread!!!");
    }

    //todo: not working
//    @Async
//    public void async1() throws InterruptedException {
//        Thread.sleep(5000);
//        System.out.println(Thread.currentThread().getName());
//        System.out.println("async1");
//    }
//
//    @Async
//    public void async2() throws InterruptedException {
//        Thread.sleep(5000);
//        System.out.println(Thread.currentThread().getName());
//        System.out.println("async2");
//    }

    public CompletableFuture<String> placeOrder(Order order) {
        // Save order in DB
//        order = orderRepository.save(order);

        // Process payment asynchronously
        return asyncService.processPayment(order)
                .thenCompose(paymentSuccess -> {
                    if (paymentSuccess) {
                        order.setPaymentProcessed(true);
//                        orderRepository.save(order);
                        // Proceed with sending email asynchronously
                        return asyncService.sendOrderConfirmation(order.getCustomerEmail(), order.getId())
                                .thenApply(emailSuccess -> {
                                    if (emailSuccess) {
                                        return "✅ Order Successful, Email Sent!";
                                    } else {
                                        return "⚠️ Order Successful, But Email Sending Failed!";
                                    }
                                });
                    } else {
                        return CompletableFuture.completedFuture("❌ Order Unsuccessful, Payment Failed!");
                    }
                });
    }

    public CompletableFuture<String> placeFoodOrder(FoodOrder order) {
//        order = orderRepository.save(order); // Save order (10ms)

        return asyncService.processPayment(order)
                .thenCompose(paymentSuccess -> {
                    if (!paymentSuccess) {
                        return CompletableFuture.completedFuture("❌ Order Unsuccessful, Payment Failed!");
                    }

                    // Notify Restaurant and Assign Delivery Partner in parallel
                    CompletableFuture<Boolean> restaurantFuture = asyncService.notifyRestaurant(order);
                    CompletableFuture<Boolean> deliveryFuture = restaurantFuture.thenCompose(restaurantNotified -> {
                        if (restaurantNotified) {
                            return asyncService.assignRider(order);
                        } else {
                            return CompletableFuture.completedFuture(false);
                        }
                    });

                    // Send Email while processing restaurant + delivery
                    CompletableFuture<Boolean> emailFuture = asyncService.sendOrderConfirmation(order.getCustomerEmail(), order.getId());

                    return CompletableFuture.allOf(restaurantFuture, deliveryFuture, emailFuture)
                            .thenApply(v -> {
                                boolean restaurantNotified = restaurantFuture.join();
                                boolean deliveryAssigned = deliveryFuture.join();
                                boolean emailSent = emailFuture.join();

                                if (!restaurantNotified) {
                                    return "⚠️ Payment Successful, But Restaurant Notification Failed!";
                                } else if (!deliveryAssigned) {
                                    return "⚠️ Order Placed, But No Delivery Partner Found!";
                                } else if (!emailSent) {
                                    return "✅ Order Placed, But Email Sending Failed!";
                                }
                                return "✅ Order Placed, Rider Assigned!";
                            });
                });
    }

    @Override
    public void startEvenOddPrintig() {
        ExecutorService executorService = Executors.newFixedThreadPool(2);
        EvenOddPrinter printer = new EvenOddPrinter();
        executorService.submit(() -> {
            try {
                printer.printOdd();
            } catch (InterruptedException e) {
                throw new RuntimeException(e);
            }
        });
        executorService.submit(() -> {
            try {
                printer.printEven();
            } catch (InterruptedException e) {
                throw new RuntimeException(e);
            }
        });
        executorService.shutdown();
    }

    @Override
    public void produceConsume() {
        BlockingQueue<Integer> q1 = new LinkedBlockingQueue<>();
        BlockingQueue<Integer> q2 = new LinkedBlockingQueue<>();
        ExecutorService executorService = Executors.newFixedThreadPool(3);

        executorService.submit(() -> {
            try {
                for (int i = 1; i <= 10; i++) {
                    q1.put(i);
                    Thread.sleep(1000);
                }
            } catch (InterruptedException e) {
                throw new RuntimeException(e);
            }
        });

        executorService.submit(() -> {
            try {
                while (true) {
                    Integer num;
                    num = q1.take();
                    if (num != -1) {
                        q2.put(num * num);
                    } else {
                        q2.put(-1);
                        break;
                    }
                }
            } catch (InterruptedException e) {
                throw new RuntimeException();
            }
        });
        executorService.submit(() -> {
            while (true) {
                Integer squaredNum;
                try {
                    squaredNum = q2.take();
                } catch (InterruptedException e) {
                    throw new RuntimeException(e);
                }
                if (squaredNum == -1) {
                    break;
                }
                System.out.println(squaredNum);
            }
        });
    }
}
