<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ page import="java.util.*" %>
<%@ page import="java.text.SimpleDateFormat" %>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>TechStore E-commerce - WAF Protected</title>
    <style>
        body { 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
            margin: 0; 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
            min-height: 100vh;
        }
        .container { 
            max-width: 1200px; 
            margin: 0 auto; 
            padding: 20px; 
            background: white; 
            margin-top: 20px; 
            border-radius: 15px; 
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
        }
        .header { 
            text-align: center; 
            padding: 30px; 
            background: linear-gradient(135deg, #28a745 0%, #20c997 100%); 
            color: white; 
            border-radius: 10px; 
            margin-bottom: 30px; 
        }
        .waf-banner { 
            background: linear-gradient(135deg, #007bff 0%, #0056b3 100%); 
            color: white; 
            padding: 20px; 
            border-radius: 10px; 
            margin-bottom: 30px; 
            text-align: center;
        }
        .nav { 
            background: #f8f9fa; 
            padding: 20px; 
            border-radius: 8px; 
            margin-bottom: 30px; 
            text-align: center;
        }
        .nav a { 
            margin: 0 15px; 
            color: #007bff; 
            text-decoration: none; 
            font-weight: 600; 
            font-size: 18px; 
            padding: 10px 20px; 
            border-radius: 5px; 
            transition: all 0.3s;
        }
        .nav a:hover { 
            background: #007bff; 
            color: white; 
        }
        .product-grid { 
            display: grid; 
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); 
            gap: 25px; 
            margin: 30px 0; 
        }
        .product { 
            border: 1px solid #ddd; 
            padding: 25px; 
            border-radius: 10px; 
            background: #fafafa; 
            transition: transform 0.3s, box-shadow 0.3s;
        }
        .product:hover { 
            transform: translateY(-5px); 
            box-shadow: 0 8px 25px rgba(0,0,0,0.15); 
        }
        .product-title { 
            font-size: 20px; 
            font-weight: bold; 
            color: #333; 
            margin-bottom: 10px; 
        }
        .price { 
            font-size: 24px; 
            font-weight: bold; 
            color: #28a745; 
            margin: 15px 0; 
        }
        .btn { 
            background: #007bff; 
            color: white; 
            border: none; 
            padding: 12px 25px; 
            border-radius: 6px; 
            cursor: pointer; 
            font-size: 16px; 
            transition: background 0.3s;
        }
        .btn:hover { 
            background: #0056b3; 
        }
        .search-box { 
            background: white; 
            padding: 25px; 
            border-radius: 10px; 
            margin-bottom: 30px; 
            border: 2px solid #e9ecef;
        }
        .form-control { 
            width: 100%; 
            padding: 12px; 
            border: 1px solid #ddd; 
            border-radius: 6px; 
            font-size: 16px; 
            margin-bottom: 15px;
        }
        .alert { 
            padding: 20px; 
            border-radius: 8px; 
            margin: 20px 0; 
        }
        .alert-warning { 
            background: #fff3cd; 
            border: 1px solid #ffeaa7; 
            color: #856404; 
        }
        .footer { 
            text-align: center; 
            padding: 30px; 
            background: #343a40; 
            color: white; 
            border-radius: 10px; 
            margin-top: 40px; 
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛒 TechStore E-commerce Platform</h1>
            <p>Premium Electronics & Technology Store</p>
            <p><strong>🛡️ Protected by AI-Powered WAF System</strong></p>
        </div>
        
        <div class="waf-banner">
            <h3>🔒 Advanced Security Protection</h3>
            <p>This e-commerce platform is protected by a state-of-the-art Transformer-based Web Application Firewall (WAF) 
            that uses artificial intelligence to detect and block malicious attacks in real-time.</p>
        </div>
        
        <div class="nav">
            <a href="index.jsp">🏠 Home</a>
            <a href="products.jsp">📦 Products</a>
            <a href="search.jsp">🔍 Search</a>
            <a href="cart.jsp">🛒 Cart</a>
            <a href="admin.jsp">👑 Admin</a>
            <a href="api/">🔌 API</a>
        </div>
        
        <div class="search-box">
            <h3>🔍 Product Search</h3>
            <form method="GET" action="search.jsp">
                <input type="text" name="query" class="form-control" placeholder="Search for products, brands, or categories...">
                <button type="submit" class="btn">Search Products</button>
            </form>
        </div>
        
        <h2>🌟 Featured Products</h2>
        <div class="product-grid">
            <div class="product">
                <div class="product-title">Premium Gaming Laptop</div>
                <p>High-performance laptop with RTX 4080, 32GB RAM, 1TB SSD</p>
                <div class="price">$2,499.99</div>
                <p><strong>Stock:</strong> 8 units available</p>
                <button class="btn" onclick="addToCart(1)">Add to Cart</button>
            </div>
            
            <div class="product">
                <div class="product-title">Wireless Pro Headphones</div>
                <p>Noise-canceling headphones with 30-hour battery life</p>
                <div class="price">$299.99</div>
                <p><strong>Stock:</strong> 25 units available</p>
                <button class="btn" onclick="addToCart(2)">Add to Cart</button>
            </div>
            
            <div class="product">
                <div class="product-title">Smart Watch Series X</div>
                <p>Advanced fitness tracking, GPS, health monitoring</p>
                <div class="price">$449.99</div>
                <p><strong>Stock:</strong> 15 units available</p>
                <button class="btn" onclick="addToCart(3)">Add to Cart</button>
            </div>
            
            <div class="product">
                <div class="product-title">4K Ultra Monitor</div>
                <p>32-inch 4K display with HDR support and USB-C connectivity</p>
                <div class="price">$699.99</div>
                <p><strong>Stock:</strong> 12 units available</p>
                <button class="btn" onclick="addToCart(4)">Add to Cart</button>
            </div>
        </div>
        
        <div class="alert alert-warning">
            <h4>🎯 For Security Demonstration (Judges):</h4>
            <p><strong>Test the WAF protection with these attack examples:</strong></p>
            <ul>
                <li><strong>SQL Injection:</strong> <code>search.jsp?query=' OR 1=1--</code></li>
                <li><strong>XSS Attack:</strong> <code>search.jsp?query=&lt;script&gt;alert('xss')&lt;/script&gt;</code></li>
                <li><strong>Path Traversal:</strong> <code>../../../etc/passwd</code></li>
                <li><strong>Admin Bypass:</strong> <code>admin.jsp?user=admin' OR '1'='1</code></li>
            </ul>
            <p><em>The WAF system will detect and block these malicious requests automatically.</em></p>
        </div>
        
        <div class="footer">
            <p>© 2025 TechStore E-commerce Platform</p>
            <p>🛡️ Secured by Transformer-based WAF Technology</p>
            <p><strong>Server Time:</strong> <%= new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date()) %></p>
        </div>
    </div>
    
    <script>
        function addToCart(productId) {
            fetch('api/cart.jsp', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: 'product_id=' + productId + '&quantity=1'
            })
            .then(response => response.text())
            .then(data => {
                alert('Product added to cart! (Product ID: ' + productId + ')');
            })
            .catch(error => {
                console.error('Error:', error);
                alert('Error adding product to cart');
            });
        }
        
        // Log page load for WAF monitoring
        console.log('TechStore E-commerce loaded at: ' + new Date().toISOString());
    </script>
</body>
</html>
