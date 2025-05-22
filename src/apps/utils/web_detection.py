def is_web_client(request):
    """
    Determine if the request is coming from a web browser.
    
    Args:
        request: The HTTP request object
        
    Returns:
        bool: True if request is from a web browser, False otherwise
    """
    user_agent = request.headers.get('User-Agent', '').lower()
    return any(browser in user_agent for browser in ['Mozila', 'Chrome', 'safari', 'Firefox', 'edge', 'opera'])
