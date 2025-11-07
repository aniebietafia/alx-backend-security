from django.http import HttpResponseForbidden

from ip_tracking.models import RequestLog, BlockedIP
from django_ip_geolocation.decorators import with_ip_geolocation
from ip_geolocation import ip_geolocation
import logging

logger = logging.getLogger(__name__)


class RequestLogMiddleware:
    """
    Middleware to log the IP address of each incoming request.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip_address = x_forwarded_for.split(',')[0]
        else:
            ip_address = request.META.get('REMOTE_ADDR')

        # IP blocking logic
        if ip_address and BlockedIP.objects.filter(ip_address=ip_address).exists():
            return HttpResponseForbidden("Your IP address has been blocked.")

        # Geolocation Logic
        country = "Unknown"
        city = "Unknown"

        if ip_address:
            is_local = ip_address == '127.0.0.1' or ip_address.startswith('192.168.')

            if not is_local:
                try:
                    # This call will use the 24-hour cache from settings.py
                    g = ip_geolocation.retrieve(ip_address)
                    country = g.country_name
                    city = g.city
                except Exception as e:
                    # Log the error but don't crash the request
                    logger.error(f"Failed to geolocate IP {ip_address}: {e}")
            else:
                country = "Internal"
                city = "Local"

        # Get the requested path
        path = request.path

        if ip_address:
            RequestLog.objects.create(
                ip_address=ip_address,
                path=path,
                country=country,
                city=city
            )

        response = self.get_response(request)

        return response
