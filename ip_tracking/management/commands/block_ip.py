import re

from django.core.management import BaseCommand

from ip_tracking.models import BlockedIP


class Command(BaseCommand):
    help = 'Adds one or more IP addresses to the blocked list.'

    def add_arguments(self, parser):
        parser.add_argument('ip_addresses', nargs='+', type=str, help='The IP address(es) to block')

    def handle(self, *args, **kwargs):
        ip_addresses = kwargs['ip_addresses']

        ip_regex = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")

        for ip in ip_addresses:
            if not ip_regex.match(ip):
                self.stderr.write(self.style.ERROR(f"Invalid IP address format: {ip}"))
                continue

            blocked_ip, created = BlockedIP.objects.get_or_create(ip_address=ip)
            if created:
                self.stdout.write(self.style.SUCCESS(f"Successfully blocked IP address: {ip}"))
            else:
                self.stdout.write(self.style.WARNING(f"IP address already blocked: {ip}"))