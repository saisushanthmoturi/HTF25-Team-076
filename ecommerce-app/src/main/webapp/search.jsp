<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ page import="java.net.URLDecoder" %>
<!DOCTYPE html>
<html>
<head>
    <title>Product Search - TechStore</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
        .container { max-width: 1000px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; }
        .header { background: #28a745; color: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; }
        .search-result { border: 1px solid #ddd; padding: 20px; margin: 15px 0; border-radius: 8px; }
        .alert { background: #f8d7da; padding: 15px; border-radius: 5px; margin: 20px 0; color: #721c24; }
        .form-control { width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 5px; margin-bottom: 10px; }
        .btn { background: #007bff; color: white; border: none; padding: 10px 20px; border-radius: 5px; cursor: pointer; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 Product Search</h1>
            <p>Search our extensive product catalog</p>
        </div>
        
        <form method="GET">
            <input type="text" name="query" class="form-control" placeholder="Search products..." 
                   value="<%= request.getParameter("query") != null ? request.getParameter("query") : "" %>">
            <button type="submit" class="btn">Search</button>
        </form>
        
        <%
            String query = request.getParameter("query");
            if (query != null && !query.trim().isEmpty()) {
                // Log the search query for WAF analysis
                System.out.println("Search query: " + query);
                
                // Check for potential SQL injection patterns
                String lowerQuery = query.toLowerCase();
                boolean suspiciousQuery = lowerQuery.contains("'") || lowerQuery.contains("or 1=1") || 
                                        lowerQuery.contains("union") || lowerQuery.contains("--") ||
                                        lowerQuery.contains("<script") || lowerQuery.contains("javascript:");
                
                if (suspiciousQuery) {
        %>
                    <div class="alert">
                        <strong>⚠️ Security Warning:</strong> Suspicious search query detected! 
                        This request has been logged and flagged for security review.
                        <br><strong>Query:</strong> <%= query %>
                    </div>
        <%
                } else {
        %>
                    <h3>Search Results for: "<%= query %>"</h3>
                    <div class="search-result">
                        <h4>Gaming Laptop Pro</h4>
                        <p>High-performance gaming laptop matching your search criteria.</p>
                        <p><strong>Price:</strong> $1,299.99</p>
                    </div>
                    <div class="search-result">
                        <h4>Wireless Gaming Mouse</h4>
                        <p>Precision gaming mouse with RGB lighting.</p>
                        <p><strong>Price:</strong> $79.99</p>
                    </div>
        <%
                }
            }
        %>
        
        <div style="margin-top: 30px;">
            <a href="index.jsp" class="btn">← Back to Home</a>
        </div>
    </div>
</body>
</html>
