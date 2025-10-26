<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<!DOCTYPE html>
<html>
<head>
    <title>Admin Panel - TechStore</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
        .container { max-width: 800px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; }
        .header { background: #dc3545; color: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; }
        .form-group { margin: 15px 0; }
        .form-control { width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 5px; }
        .btn { background: #007bff; color: white; border: none; padding: 10px 20px; border-radius: 5px; cursor: pointer; }
        .alert { background: #f8d7da; padding: 15px; border-radius: 5px; margin: 20px 0; color: #721c24; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>👑 Admin Panel</h1>
            <p>Administrative access to TechStore system</p>
        </div>
        
        <div class="alert">
            <strong>🔒 Security Notice:</strong> This area requires administrator authentication.
            All access attempts are monitored and logged.
        </div>
        
        <%
            String user = request.getParameter("user");
            String pass = request.getParameter("pass");
            
            if (user != null && pass != null) {
                // Log authentication attempt
                System.out.println("Admin login attempt - User: " + user + ", Pass: [HIDDEN]");
                
                // Check for SQL injection in auth parameters
                String lowerUser = user.toLowerCase();
                boolean suspiciousAuth = lowerUser.contains("'") || lowerUser.contains("or ") || 
                                       lowerUser.contains("union") || lowerUser.contains("--");
                
                if (suspiciousAuth) {
        %>
                    <div class="alert">
                        <strong>🚨 SECURITY ALERT:</strong> SQL injection attempt detected in authentication!
                        <br><strong>User:</strong> <%= user %>
                        <br>This incident has been logged and reported to security team.
                    </div>
        <%
                } else if ("admin".equals(user) && "admin123".equals(pass)) {
        %>
                    <div style="background: #d4edda; color: #155724; padding: 15px; border-radius: 5px;">
                        <h3>✅ Authentication Successful</h3>
                        <p>Welcome, Administrator! You have successfully logged in.</p>
                        <p><strong>Admin Dashboard Features:</strong></p>
                        <ul>
                            <li>Product Management</li>
                            <li>User Administration</li>
                            <li>Security Monitoring</li>
                            <li>Sales Analytics</li>
                        </ul>
                    </div>
        <%
                } else {
        %>
                    <div class="alert">
                        <strong>❌ Authentication Failed:</strong> Invalid credentials provided.
                    </div>
        <%
                }
            }
        %>
        
        <form method="POST">
            <div class="form-group">
                <label><strong>Username:</strong></label>
                <input type="text" name="user" class="form-control" placeholder="Enter admin username">
            </div>
            <div class="form-group">
                <label><strong>Password:</strong></label>
                <input type="password" name="pass" class="form-control" placeholder="Enter admin password">
            </div>
            <button type="submit" class="btn">Login to Admin Panel</button>
        </form>
        
        <div style="margin-top: 30px; padding: 15px; background: #e9ecef; border-radius: 5px;">
            <p><strong>Demo Credentials for Testing:</strong></p>
            <ul>
                <li>Username: admin</li>
                <li>Password: admin123</li>
            </ul>
            <p><em>Try SQL injection attacks to test WAF protection!</em></p>
        </div>
        
        <div style="margin-top: 20px;">
            <a href="index.jsp" class="btn">← Back to Home</a>
        </div>
    </div>
</body>
</html>
