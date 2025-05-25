def is_web_client(request):
    """
    Determine if the request is coming from a web browser or frontend app.
    """
    user_agent = request.headers.get('User-Agent', '').lower()
    origin = request.headers.get('Origin', '')
    
    # Check if request is from our frontend app
    if origin and any(allowed in origin for allowed in ['localhost', 'netlify.app', '.onrender.com']):
        return True
        
    # Check if request is from a browser
    return any(browser in user_agent for browser in ['Mozilla', 'Chrome', 'Safari', 'Firefox', 'Edge', 'Opera'])
