<%@ page contentType="text/html;charset=UTF-8" language="java" isErrorPage="true" %>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Error - REST API App</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 40px;
            background-color: #f5f5f5;
            text-align: center;
        }
        .error-container {
            max-width: 600px;
            margin: 0 auto;
            background-color: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        .error-code {
            font-size: 72px;
            color: #dc3545;
            margin: 0;
        }
        .error-message {
            color: #6c757d;
            margin: 20px 0;
        }
        .back-link {
            color: #007bff;
            text-decoration: none;
        }
        .back-link:hover {
            text-decoration: underline;
        }
    </style>
</head>
<body>
    <div class="error-container">
        <h1 class="error-code">
            <%= request.getAttribute("javax.servlet.error.status_code") != null ? 
                request.getAttribute("javax.servlet.error.status_code") : "Error" %>
        </h1>
        
        <h2>Oops! Something went wrong</h2>
        
        <p class="error-message">
            <% 
                String errorMsg = (String) request.getAttribute("javax.servlet.error.message");
                if (errorMsg != null && !errorMsg.isEmpty()) {
                    out.println(errorMsg);
                } else {
                    out.println("The requested resource could not be found or there was an internal error.");
                }
            %>
        </p>
        
        <p>
            <a href="index.jsp" class="back-link">← Back to Home</a>
        </p>
        
        <p style="font-size: 12px; color: #aaa; margin-top: 30px;">
            Timestamp: <%= new java.util.Date() %>
        </p>
    </div>
</body>
</html>
