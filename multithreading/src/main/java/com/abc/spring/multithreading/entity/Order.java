package com.abc.spring.multithreading.entity;


import lombok.Getter;
import lombok.Setter;

import java.time.LocalDateTime;
@Getter
@Setter
public class Order {
    private Long id;
    private String customerEmail;
    private String product;
    private double amount;
    private boolean paymentProcessed;
    private LocalDateTime orderDate = LocalDateTime.now();
}
