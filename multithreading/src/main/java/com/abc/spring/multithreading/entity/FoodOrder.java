package com.abc.spring.multithreading.entity;


import lombok.Getter;
import lombok.Setter;

import java.time.LocalDateTime;

@Getter
@Setter
public class FoodOrder {
    private Long id;

    private String customerEmail;  // Customer Email
    private String restaurantName; // Restaurant Name
    private Double amount;         // Order Amount

    private boolean paymentProcessed;       // Payment success/failure
    private boolean restaurantNotified;     // Restaurant notification status
    private boolean riderAssigned;
}
