<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>REST API Test Application</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 40px;
            background-color: #f5f5f5;
        }
        .container {
            max-width: 800px;
            margin: 0 auto;
            background-color: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        h1 {
            color: #2c3e50;
            text-align: center;
        }
        .endpoint {
            background-color: #f8f9fa;
            padding: 15px;
            margin: 10px 0;
            border-radius: 5px;
            border-left: 4px solid #007bff;
        }
        .method {
            font-weight: bold;
            color: #28a745;
        }
        .method.post { color: #ffc107; }
        .method.put { color: #17a2b8; }
        .method.delete { color: #dc3545; }
        button {
            background-color: #007bff;
            color: white;
            border: none;
            padding: 10px 20px;
            border-radius: 5px;
            cursor: pointer;
            margin: 5px;
        }
        button:hover {
            background-color: #0056b3;
        }
        #output {
            background-color: #f8f9fa;
            border: 1px solid #dee2e6;
            padding: 15px;
            margin-top: 20px;
            border-radius: 5px;
            white-space: pre-wrap;
            max-height: 300px;
            overflow-y: auto;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🚀 REST API Test Application</h1>
        <p style="text-align: center; color: #6c757d;">
            This application provides various REST endpoints for testing WAF anomaly detection
        </p>
        
        <h2>Available Endpoints:</h2>
        
        <div class="endpoint">
            <span class="method">GET</span> /api/ - API Information
        </div>
        
        <div class="endpoint">
            <span class="method">GET</span> /api/users - List all users
        </div>
        
        <div class="endpoint">
            <span class="method">GET</span> /api/users/{id} - Get user by ID
        </div>
        
        <div class="endpoint">
            <span class="method">GET</span> /api/products - List all products
        </div>
        
        <div class="endpoint">
            <span class="method">GET</span> /api/products/{id} - Get product by ID
        </div>
        
        <div class="endpoint">
            <span class="method post">POST</span> /api/login - User login
        </div>
        
        <div class="endpoint">
            <span class="method post">POST</span> /api/register - User registration
        </div>
        
        <div class="endpoint">
            <span class="method">GET</span> /api/status - API status
        </div>
        
        <div class="endpoint">
            <span class="method">GET</span> /api/health - Health check
        </div>
        
        <h2>Test Endpoints:</h2>
        <button onclick="testEndpoint('/api/')">API Info</button>
        <button onclick="testEndpoint('/api/users')">Get Users</button>
        <button onclick="testEndpoint('/api/products')">Get Products</button>
        <button onclick="testEndpoint('/api/status')">Status</button>
        <button onclick="testEndpoint('/api/health')">Health</button>
        <button onclick="testLogin()">Test Login</button>
        
        <h3>Response:</h3>
        <div id="output">Click a button above to test an endpoint...</div>
    </div>

    <script>
        function testEndpoint(endpoint) {
            const output = document.getElementById('output');
            output.textContent = 'Loading...';
            
            fetch('rest-api-app' + endpoint)
                .then(response => response.json())
                .then(data => {
                    output.textContent = JSON.stringify(data, null, 2);
                })
                .catch(error => {
                    output.textContent = 'Error: ' + error.message;
                });
        }
        
        function testLogin() {
            const output = document.getElementById('output');
            output.textContent = 'Testing login...';
            
            fetch('rest-api-app/api/login', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    username: 'testuser',
                    password: 'testpass'
                })
            })
            .then(response => response.json())
            .then(data => {
                output.textContent = JSON.stringify(data, null, 2);
            })
            .catch(error => {
                output.textContent = 'Error: ' + error.message;
            });
        }
    </script>
</body>
</html>