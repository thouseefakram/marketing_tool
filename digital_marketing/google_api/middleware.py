from django.conf import settings

# middleware.py
class CookieDebugMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        print("[Cookies] Request cookies:", request.COOKIES)
        response = self.get_response(request)
        if hasattr(response, 'cookies'):
            print("[Cookies] Response cookies:", {k: v.value for k, v in response.cookies.items()})
        return response