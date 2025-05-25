import logging

logger = logging.getLogger(__name__)

def is_web_client(request):
    """
    Determine if the request is coming from a web browser or frontend app.
    """
    user_agent = request.headers.get('User-Agent', '').lower()
    origin = request.headers.get('Origin', '')
    referer = request.headers.get('Referer', '')
    
    logger.debug(f"Web detection - User-Agent: {user_agent}")
    logger.debug(f"Web detection - Origin: {origin}")
    logger.debug(f"Web detection - Referer: {referer}")
    
    # Check if request is from our frontend app (by origin or referer)
    frontend_domains = ['localhost', 'netlify.app', '.onrender.com', '127.0.0.1']
    
    # Check origin first
    if origin:
        for domain in frontend_domains:
            if domain in origin:
                logger.debug(f"Web detection - Matched origin domain: {domain}")
                return True
    
    # Check referer as fallback
    if referer:
        for domain in frontend_domains:
            if domain in referer:
                logger.debug(f"Web detection - Matched referer domain: {domain}")
                return True
    
    # Check if request is from a browser (by user agent)
    browser_indicators = ['mozilla', 'chrome', 'safari', 'firefox', 'edge', 'opera', 'webkit']
    for browser in browser_indicators:
        if browser in user_agent:
            logger.debug(f"Web detection - Matched browser indicator: {browser}")
            return True
    
    # Additional check for common frontend frameworks
    if 'fetch' in user_agent or 'axios' in user_agent:
        logger.debug(f"Web detection - Matched frontend framework indicator")
        return True
    
    logger.debug(f"Web detection - No match found, returning False")
    return False
