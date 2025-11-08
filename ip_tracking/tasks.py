from celery import shared_task
from django.utils import timezone
from django.db.models import Count, Q
from datetime import timedelta
from .models import RequestLog, SuspiciousIP


@shared_task(name="ip_tracking.check_suspicious_ips")
def check_suspicious_ips():
    """
    Celery task to detect suspicious IP activity in the last hour.
    """
    print("Running check_suspicious_ips task...")
    one_hour_ago = timezone.now() - timedelta(hours=1)

    # Find IPs exceeding 100 requests in the last hour
    volume_ips = RequestLog.objects.filter(
        timestamp__gte=one_hour_ago
    ).values(
        'ip_address'
    ).annotate(
        count=Count('ip_address')
    ).filter(
        count__gt=100
    )

    for item in volume_ips:
        reason = f"Exceeded 100 requests in one hour ({item['count']} requests)"
        obj, created = SuspiciousIP.objects.get_or_create(
            ip_address=item['ip_address'],
            reason=reason
        )
        if created:
            print(f"Flagged {item['ip_address']} for reason: {reason}")

    # Find IPs accessing sensitive paths in the last hour
    sensitive_paths_query = Q(path__startswith='/admin') | Q(path__startswith='/login')

    path_ips = RequestLog.objects.filter(
        timestamp__gte=one_hour_ago
    ).filter(
        sensitive_paths_query
    ).values_list(
        'ip_address', flat=True
    ).distinct()

    reason = "Accessed sensitive path (e.g., /admin, /login)"
    for ip in path_ips:
        obj, created = SuspiciousIP.objects.get_or_create(
            ip_address=ip,
            reason=reason
        )
        if created:
            print(f"Flagged {ip} for reason: {reason}")

    return f"Suspicious IP check complete. Found {volume_ips.count()} volume-based IPs and {path_ips.count()} path-based IPs."