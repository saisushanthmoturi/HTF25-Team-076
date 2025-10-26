#!/usr/bin/env python3
"""
Blog CMS Demo Application
========================
A vulnerable blog application for WAF testing and demonstration
"""

from flask import Flask, request, jsonify, render_template_string
import json
import time
from datetime import datetime
import logging
import os

app = Flask(__name__)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('blog_cms_access.log'),
        logging.StreamHandler()
    ]
)

# Mock blog data
BLOG_POSTS = [
    {
        "id": 1,
        "title": "Welcome to TechBlog CMS",
        "content": "This is our new AI-protected blog platform featuring cutting-edge security.",
        "author": "Admin",
        "date": "2025-10-26",
        "tags": ["welcome", "security", "ai"],
        "comments": [
            {"id": 1, "author": "User1", "content": "Great platform!", "date": "2025-10-26"}
        ]
    },
    {
        "id": 2,
        "title": "AI-Powered Web Security",
        "content": "Learn about our Transformer-based WAF system that protects against modern attacks.",
        "author": "Security Team",
        "date": "2025-10-25",
        "tags": ["ai", "security", "waf"],
        "comments": [
            {"id": 2, "author": "Developer", "content": "Impressive technology!", "date": "2025-10-25"}
        ]
    },
    {
        "id": 3,
        "title": "Blog Platform Features",
        "content": "Explore the features of our content management system including real-time editing.",
        "author": "Product Team",
        "date": "2025-10-24",
        "tags": ["cms", "features", "blogging"],
        "comments": []
    }
]

USERS = {
    "admin": {"password": "admin123", "role": "admin"},
    "editor": {"password": "editor123", "role": "editor"},
    "user": {"password": "user123", "role": "user"}
}

HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>TechBlog CMS - AI Protected</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; background: #f8f9fa; }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        .header { background: linear-gradient(135deg, #28a745 0%, #20c997 100%); color: white; padding: 30px; border-radius: 10px; margin-bottom: 30px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
        .nav { background: white; padding: 15px; border-radius: 8px; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .nav a { margin-right: 25px; color: #007bff; text-decoration: none; font-weight: 600; font-size: 16px; }
        .nav a:hover { text-decoration: underline; color: #0056b3; }
        .waf-status { background: linear-gradient(135deg, #e3f2fd 0%, #bbdefb 100%); border-left: 5px solid #2196f3; padding: 20px; margin: 20px 0; border-radius: 8px; }
        .post { background: white; padding: 25px; margin: 20px 0; border-radius: 10px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }
        .post-title { color: #333; font-size: 24px; margin-bottom: 10px; }
        .post-meta { color: #666; font-size: 14px; margin-bottom: 15px; }
        .post-content { line-height: 1.6; margin-bottom: 20px; }
        .tags { margin: 15px 0; }
        .tag { background: #e9ecef; padding: 5px 10px; border-radius: 15px; font-size: 12px; margin-right: 8px; display: inline-block; }
        .comment { background: #f8f9fa; padding: 15px; margin: 10px 0; border-radius: 8px; border-left: 3px solid #28a745; }
        .btn { background: #007bff; color: white; border: none; padding: 12px 20px; border-radius: 6px; cursor: pointer; font-size: 16px; }
        .btn:hover { background: #0056b3; }
        .btn-success { background: #28a745; }
        .btn-success:hover { background: #218838; }
        .btn-danger { background: #dc3545; }
        .btn-danger:hover { background: #c82333; }
        .form-group { margin: 15px 0; }
        .form-control { width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 6px; font-size: 16px; }
        .alert { padding: 15px; border-radius: 6px; margin: 20px 0; }
        .alert-info { background: #d1ecf1; border: 1px solid #bee5eb; color: #0c5460; }
        .alert-warning { background: #fff3cd; border: 1px solid #ffeaa7; color: #856404; }
        .search-box { background: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>📝 TechBlog CMS</h1>
            <p>🛡️ AI-Protected Content Management System</p>
        </div>
        
        <div class="waf-status">
            <strong>🔒 Security Status:</strong> This blog platform is protected by an advanced Transformer-based WAF system
            that analyzes and blocks malicious requests in real-time. All content and user interactions are monitored for security threats.
        </div>
        
        <div class="nav">
            <a href="/">🏠 Home</a>
            <a href="/posts">📝 All Posts</a>
            <a href="/search">🔍 Search</a>
            <a href="/admin">👑 Admin</a>
            <a href="/api/posts">🔌 API</a>
            <a href="/editor">✏️ Editor</a>
        </div>
        
        {{ content }}
    </div>
</body>
</html>
"""

@app.before_request
def log_request():
    """Log all incoming requests"""
    app.logger.info(f"Blog Request: {request.method} {request.url} from {request.remote_addr}")

@app.route('/')
def home():
    content = """
    <h2>Welcome to TechBlog CMS!</h2>
    <div class="alert alert-info">🛡️ This content management system is protected by our AI-powered WAF</div>
    
    <div class="search-box">
        <h3>🔍 Search Blog Posts</h3>
        <form method="GET" action="/search">
            <div class="form-group">
                <input type="text" name="q" class="form-control" placeholder="Search posts, tags, or content..." style="margin-bottom: 10px;">
                <button type="submit" class="btn">Search Posts</button>
            </div>
        </form>
    </div>
    
    <h3>📝 Latest Blog Posts</h3>
    """
    
    # Show latest 2 posts
    for post in BLOG_POSTS[:2]:
        content += f"""
        <div class="post">
            <h3 class="post-title">{post['title']}</h3>
            <div class="post-meta">By {post['author']} • {post['date']} • {len(post['comments'])} comments</div>
            <div class="post-content">{post['content'][:200]}...</div>
            <div class="tags">
                {' '.join([f'<span class="tag">{tag}</span>' for tag in post['tags']])}
            </div>
            <a href="/posts/{post['id']}" class="btn">Read More</a>
        </div>
        """
    
    content += """
    <div style="background: #fff3cd; padding: 20px; border-radius: 8px; margin-top: 30px;">
        <strong>🎬 For Judges - Attack Testing Examples:</strong>
        <ul>
            <li>SQL Injection: <code>/search?q=' OR 1=1--</code></li>
            <li>XSS: <code>/search?q=&lt;script&gt;alert('xss')&lt;/script&gt;</code></li>
            <li>Admin Access: <code>/admin?user=admin&pass=admin123</code></li>
            <li>Path Traversal: <code>/api/posts/../../../etc/passwd</code></li>
        </ul>
        <p><em>Try these attacks to see the WAF protection in action!</em></p>
    </div>
    """
    
    return render_template_string(HTML_TEMPLATE, content=content)

@app.route('/posts')
def all_posts():
    content = "<h2>📝 All Blog Posts</h2>"
    
    for post in BLOG_POSTS:
        content += f"""
        <div class="post">
            <h3 class="post-title">{post['title']}</h3>
            <div class="post-meta">By {post['author']} • {post['date']} • {len(post['comments'])} comments</div>
            <div class="post-content">{post['content']}</div>
            <div class="tags">
                {' '.join([f'<span class="tag">{tag}</span>' for tag in post['tags']])}
            </div>
            <div style="margin-top: 15px;">
                <a href="/posts/{post['id']}" class="btn">View Post</a>
                <a href="/posts/{post['id']}/edit" class="btn btn-success">Edit</a>
            </div>
        </div>
        """
    
    return render_template_string(HTML_TEMPLATE, content=content)

@app.route('/posts/<int:post_id>')
def view_post(post_id):
    post = next((p for p in BLOG_POSTS if p["id"] == post_id), None)
    if not post:
        content = "<h2>❌ Post Not Found</h2><p>The requested blog post does not exist.</p>"
        return render_template_string(HTML_TEMPLATE, content=content)
    
    content = f"""
    <div class="post">
        <h2 class="post-title">{post['title']}</h2>
        <div class="post-meta">By {post['author']} • {post['date']}</div>
        <div class="post-content" style="font-size: 18px; line-height: 1.8;">{post['content']}</div>
        <div class="tags">
            {' '.join([f'<span class="tag">{tag}</span>' for tag in post['tags']])}
        </div>
    </div>
    
    <h3>💬 Comments ({len(post['comments'])})</h3>
    """
    
    for comment in post['comments']:
        content += f"""
        <div class="comment">
            <strong>{comment['author']}</strong> • {comment['date']}
            <p>{comment['content']}</p>
        </div>
        """
    
    content += f"""
    <div style="background: white; padding: 20px; border-radius: 8px; margin-top: 20px;">
        <h4>💬 Add Comment</h4>
        <form method="POST" action="/posts/{post_id}/comment">
            <div class="form-group">
                <input type="text" name="author" class="form-control" placeholder="Your name" required>
            </div>
            <div class="form-group">
                <textarea name="content" class="form-control" rows="3" placeholder="Your comment" required></textarea>
            </div>
            <button type="submit" class="btn">Post Comment</button>
        </form>
    </div>
    """
    
    return render_template_string(HTML_TEMPLATE, content=content)

@app.route('/search')
def search():
    query = request.args.get('q', '')
    content = f"""
    <h2>🔍 Search Blog Posts</h2>
    <div class="search-box">
        <form method="GET">
            <div class="form-group">
                <input type="text" name="q" value="{query}" class="form-control" placeholder="Search posts, tags, or content...">
                <button type="submit" class="btn" style="margin-top: 10px;">Search</button>
            </div>
        </form>
    </div>
    """
    
    if query:
        # Vulnerable search (for demo purposes)
        results = []
        for post in BLOG_POSTS:
            if (query.lower() in post['title'].lower() or 
                query.lower() in post['content'].lower() or
                any(query.lower() in tag.lower() for tag in post['tags'])):
                results.append(post)
        
        content += f"<h3>Search Results for: '{query}' ({len(results)} found)</h3>"
        
        if results:
            for post in results:
                content += f"""
                <div class="post">
                    <h4 class="post-title">{post['title']}</h4>
                    <div class="post-meta">By {post['author']} • {post['date']}</div>
                    <div class="post-content">{post['content'][:150]}...</div>
                    <a href="/posts/{post['id']}" class="btn">Read More</a>
                </div>
                """
        else:
            content += "<p>No posts found matching your search criteria.</p>"
    
    return render_template_string(HTML_TEMPLATE, content=content)

@app.route('/admin')
def admin():
    content = """
    <h2>👑 Admin Panel</h2>
    <div class="alert alert-warning">
        <strong>⚠️ Administrator Access Required</strong><br>
        Please login with valid administrator credentials.
    </div>
    
    <div style="background: white; padding: 25px; border-radius: 8px;">
        <form method="POST" action="/admin/login">
            <div class="form-group">
                <label><strong>Username:</strong></label>
                <input type="text" name="username" class="form-control" placeholder="Enter username">
            </div>
            <div class="form-group">
                <label><strong>Password:</strong></label>
                <input type="password" name="password" class="form-control" placeholder="Enter password">
            </div>
            <button type="submit" class="btn">Login to Admin Panel</button>
        </form>
        
        <div style="margin-top: 20px; padding: 15px; background: #f8f9fa; border-radius: 6px;">
            <p><strong>Demo Credentials:</strong></p>
            <ul>
                <li>Admin: admin / admin123</li>
                <li>Editor: editor / editor123</li>
            </ul>
        </div>
    </div>
    """
    return render_template_string(HTML_TEMPLATE, content=content)

@app.route('/editor')
def editor():
    content = """
    <h2>✏️ Post Editor</h2>
    <div class="alert alert-info">Create and edit blog posts with our rich content editor</div>
    
    <div style="background: white; padding: 25px; border-radius: 8px;">
        <form method="POST" action="/editor/save">
            <div class="form-group">
                <label><strong>Post Title:</strong></label>
                <input type="text" name="title" class="form-control" placeholder="Enter post title">
            </div>
            <div class="form-group">
                <label><strong>Content:</strong></label>
                <textarea name="content" class="form-control" rows="8" placeholder="Write your blog post content here..."></textarea>
            </div>
            <div class="form-group">
                <label><strong>Tags (comma-separated):</strong></label>
                <input type="text" name="tags" class="form-control" placeholder="e.g., technology, security, ai">
            </div>
            <div class="form-group">
                <label><strong>Author:</strong></label>
                <input type="text" name="author" class="form-control" placeholder="Author name">
            </div>
            <button type="submit" class="btn btn-success">Publish Post</button>
            <button type="button" class="btn" onclick="alert('Draft saved!')">Save Draft</button>
        </form>
    </div>
    """
    return render_template_string(HTML_TEMPLATE, content=content)

@app.route('/api/posts')
def api_posts():
    return jsonify({
        "posts": BLOG_POSTS,
        "total": len(BLOG_POSTS),
        "api_version": "1.0",
        "protected_by": "Transformer WAF",
        "timestamp": datetime.now().isoformat()
    })

@app.route('/api/posts/<int:post_id>')
def api_get_post(post_id):
    post = next((p for p in BLOG_POSTS if p["id"] == post_id), None)
    if post:
        return jsonify(post)
    return jsonify({"error": "Post not found"}), 404

@app.route('/api/search')
def api_search():
    query = request.args.get('q', '')
    results = []
    for post in BLOG_POSTS:
        if query.lower() in post['title'].lower() or query.lower() in post['content'].lower():
            results.append(post)
    
    return jsonify({
        "query": query,
        "results": results,
        "count": len(results),
        "timestamp": datetime.now().isoformat()
    })

@app.route('/posts/<int:post_id>/comment', methods=['POST'])
def add_comment(post_id):
    author = request.form.get('author', 'Anonymous')
    content = request.form.get('content', '')
    
    return jsonify({
        "status": "success",
        "message": f"Comment added by {author}",
        "post_id": post_id,
        "timestamp": datetime.now().isoformat()
    })

if __name__ == '__main__':
    print("📝 Starting Blog CMS Application on http://localhost:5002")
    app.run(host='0.0.0.0', port=5002, debug=False)
