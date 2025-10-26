package com.api.servlet;

import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * REST API Servlet for testing WAF anomaly detection
 * Provides various endpoints that can be used to generate normal and suspicious traffic
 */
@WebServlet(urlPatterns = {"/api/*"})
public class RestAPIServlet extends HttpServlet {
    
    private ObjectMapper objectMapper = new ObjectMapper();
    private List<Map<String, Object>> users = new ArrayList<>();
    private List<Map<String, Object>> products = new ArrayList<>();
    
    @Override
    public void init() throws ServletException {
        super.init();
        initializeData();
    }
    
    private void initializeData() {
        // Initialize sample users
        for (int i = 1; i <= 10; i++) {
            Map<String, Object> user = new HashMap<>();
            user.put("id", i);
            user.put("username", "user" + i);
            user.put("email", "user" + i + "@example.com");
            user.put("role", i <= 2 ? "admin" : "user");
            users.add(user);
        }
        
        // Initialize sample products
        String[] productNames = {"Laptop", "Phone", "Tablet", "Watch", "Headphones", "Camera", "Speaker", "Monitor"};
        for (int i = 1; i <= productNames.length; i++) {
            Map<String, Object> product = new HashMap<>();
            product.put("id", i);
            product.put("name", productNames[i-1]);
            product.put("price", 100 + (i * 50));
            product.put("category", i <= 4 ? "Electronics" : "Accessories");
            products.add(product);
        }
    }
    
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) 
            throws ServletException, IOException {
        
        String pathInfo = request.getPathInfo();
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");
        
        try {
            if (pathInfo == null || pathInfo.equals("/")) {
                handleApiInfo(response);
            } else if (pathInfo.startsWith("/users")) {
                handleUsersGet(request, response);
            } else if (pathInfo.startsWith("/products")) {
                handleProductsGet(request, response);
            } else if (pathInfo.equals("/status")) {
                handleStatus(response);
            } else if (pathInfo.equals("/health")) {
                handleHealth(response);
            } else {
                sendError(response, 404, "Endpoint not found");
            }
        } catch (Exception e) {
            sendError(response, 500, "Internal server error: " + e.getMessage());
        }
    }
    
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) 
            throws ServletException, IOException {
        
        String pathInfo = request.getPathInfo();
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");
        
        try {
            if (pathInfo.equals("/login")) {
                handleLogin(request, response);
            } else if (pathInfo.equals("/register")) {
                handleRegister(request, response);
            } else if (pathInfo.startsWith("/users")) {
                handleUsersPost(request, response);
            } else if (pathInfo.startsWith("/products")) {
                handleProductsPost(request, response);
            } else {
                sendError(response, 404, "Endpoint not found");
            }
        } catch (Exception e) {
            sendError(response, 500, "Internal server error: " + e.getMessage());
        }
    }
    
    @Override
    protected void doPut(HttpServletRequest request, HttpServletResponse response) 
            throws ServletException, IOException {
        
        String pathInfo = request.getPathInfo();
        response.setContentType("application/json");
        
        try {
            if (pathInfo.startsWith("/users/")) {
                handleUsersPut(request, response);
            } else if (pathInfo.startsWith("/products/")) {
                handleProductsPut(request, response);
            } else {
                sendError(response, 404, "Endpoint not found");
            }
        } catch (Exception e) {
            sendError(response, 500, "Internal server error: " + e.getMessage());
        }
    }
    
    @Override
    protected void doDelete(HttpServletRequest request, HttpServletResponse response) 
            throws ServletException, IOException {
        
        String pathInfo = request.getPathInfo();
        response.setContentType("application/json");
        
        try {
            if (pathInfo.startsWith("/users/")) {
                handleUsersDelete(request, response);
            } else if (pathInfo.startsWith("/products/")) {
                handleProductsDelete(request, response);
            } else {
                sendError(response, 404, "Endpoint not found");
            }
        } catch (Exception e) {
            sendError(response, 500, "Internal server error: " + e.getMessage());
        }
    }
    
    private void handleApiInfo(HttpServletResponse response) throws IOException {
        Map<String, Object> info = new HashMap<>();
        info.put("name", "REST API Test Application");
        info.put("version", "1.0.0");
        info.put("description", "API for testing WAF anomaly detection");
        info.put("endpoints", new String[]{
            "GET /api/users - List all users",
            "GET /api/users/{id} - Get user by ID",
            "GET /api/products - List all products",
            "GET /api/products/{id} - Get product by ID",
            "POST /api/login - User login",
            "POST /api/register - User registration",
            "GET /api/status - API status",
            "GET /api/health - Health check"
        });
        
        sendJsonResponse(response, 200, info);
    }
    
    private void handleUsersGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String pathInfo = request.getPathInfo();
        
        if (pathInfo.equals("/users") || pathInfo.equals("/users/")) {
            // List all users
            sendJsonResponse(response, 200, users);
        } else {
            // Get specific user
            String userId = pathInfo.substring("/users/".length());
            try {
                int id = Integer.parseInt(userId);
                Map<String, Object> user = users.stream()
                    .filter(u -> u.get("id").equals(id))
                    .findFirst()
                    .orElse(null);
                
                if (user != null) {
                    sendJsonResponse(response, 200, user);
                } else {
                    sendError(response, 404, "User not found");
                }
            } catch (NumberFormatException e) {
                sendError(response, 400, "Invalid user ID");
            }
        }
    }
    
    private void handleProductsGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String pathInfo = request.getPathInfo();
        
        if (pathInfo.equals("/products") || pathInfo.equals("/products/")) {
            // List all products
            sendJsonResponse(response, 200, products);
        } else {
            // Get specific product
            String productId = pathInfo.substring("/products/".length());
            try {
                int id = Integer.parseInt(productId);
                Map<String, Object> product = products.stream()
                    .filter(p -> p.get("id").equals(id))
                    .findFirst()
                    .orElse(null);
                
                if (product != null) {
                    sendJsonResponse(response, 200, product);
                } else {
                    sendError(response, 404, "Product not found");
                }
            } catch (NumberFormatException e) {
                sendError(response, 400, "Invalid product ID");
            }
        }
    }
    
    private void handleLogin(HttpServletRequest request, HttpServletResponse response) throws IOException {
        // Simulate login
        Map<String, Object> loginResponse = new HashMap<>();
        loginResponse.put("success", true);
        loginResponse.put("token", "jwt-token-example");
        loginResponse.put("user", "authenticated_user");
        loginResponse.put("timestamp", System.currentTimeMillis());
        
        sendJsonResponse(response, 200, loginResponse);
    }
    
    private void handleRegister(HttpServletRequest request, HttpServletResponse response) throws IOException {
        // Simulate registration
        Map<String, Object> registerResponse = new HashMap<>();
        registerResponse.put("success", true);
        registerResponse.put("message", "User registered successfully");
        registerResponse.put("userId", users.size() + 1);
        
        sendJsonResponse(response, 201, registerResponse);
    }
    
    private void handleUsersPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        // Create new user
        Map<String, Object> newUser = new HashMap<>();
        newUser.put("id", users.size() + 1);
        newUser.put("username", "newuser" + (users.size() + 1));
        newUser.put("email", "newuser" + (users.size() + 1) + "@example.com");
        newUser.put("role", "user");
        
        users.add(newUser);
        sendJsonResponse(response, 201, newUser);
    }
    
    private void handleProductsPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        // Create new product
        Map<String, Object> newProduct = new HashMap<>();
        newProduct.put("id", products.size() + 1);
        newProduct.put("name", "New Product " + (products.size() + 1));
        newProduct.put("price", 299);
        newProduct.put("category", "New");
        
        products.add(newProduct);
        sendJsonResponse(response, 201, newProduct);
    }
    
    private void handleUsersPut(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String userId = request.getPathInfo().substring("/users/".length());
        Map<String, Object> updateResponse = new HashMap<>();
        updateResponse.put("success", true);
        updateResponse.put("message", "User " + userId + " updated successfully");
        
        sendJsonResponse(response, 200, updateResponse);
    }
    
    private void handleProductsPut(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String productId = request.getPathInfo().substring("/products/".length());
        Map<String, Object> updateResponse = new HashMap<>();
        updateResponse.put("success", true);
        updateResponse.put("message", "Product " + productId + " updated successfully");
        
        sendJsonResponse(response, 200, updateResponse);
    }
    
    private void handleUsersDelete(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String userId = request.getPathInfo().substring("/users/".length());
        Map<String, Object> deleteResponse = new HashMap<>();
        deleteResponse.put("success", true);
        deleteResponse.put("message", "User " + userId + " deleted successfully");
        
        sendJsonResponse(response, 200, deleteResponse);
    }
    
    private void handleProductsDelete(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String productId = request.getPathInfo().substring("/products/".length());
        Map<String, Object> deleteResponse = new HashMap<>();
        deleteResponse.put("success", true);
        deleteResponse.put("message", "Product " + productId + " deleted successfully");
        
        sendJsonResponse(response, 200, deleteResponse);
    }
    
    private void handleStatus(HttpServletResponse response) throws IOException {
        Map<String, Object> status = new HashMap<>();
        status.put("status", "running");
        status.put("timestamp", System.currentTimeMillis());
        status.put("uptime", "running");
        status.put("requests_served", "many");
        
        sendJsonResponse(response, 200, status);
    }
    
    private void handleHealth(HttpServletResponse response) throws IOException {
        Map<String, Object> health = new HashMap<>();
        health.put("healthy", true);
        health.put("database", "connected");
        health.put("memory_usage", "normal");
        health.put("timestamp", System.currentTimeMillis());
        
        sendJsonResponse(response, 200, health);
    }
    
    private void sendJsonResponse(HttpServletResponse response, int status, Object data) throws IOException {
        response.setStatus(status);
        PrintWriter out = response.getWriter();
        out.print(objectMapper.writeValueAsString(data));
        out.flush();
    }
    
    private void sendError(HttpServletResponse response, int status, String message) throws IOException {
        Map<String, Object> error = new HashMap<>();
        error.put("error", true);
        error.put("status", status);
        error.put("message", message);
        error.put("timestamp", System.currentTimeMillis());
        
        sendJsonResponse(response, status, error);
    }
}
