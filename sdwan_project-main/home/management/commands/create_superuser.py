from django.core.management.base import BaseCommand
from django.contrib.auth.models import User, Group
from home.models import Page, PagePermission

class Command(BaseCommand):
    help = 'Creates a superuser with full permissions to all pages'

    def add_arguments(self, parser):
        parser.add_argument('--username', type=str, help='Username for the superuser')
        parser.add_argument('--email', type=str, help='Email for the superuser')
        parser.add_argument('--password', type=str, help='Password for the superuser')

    def handle(self, *args, **options):
        # Get or create the admin group
        admin_group, created = Group.objects.get_or_create(name='Full Access')
        
        # Get all pages
        pages = Page.objects.all()
        
        # Create or update permissions for all pages
        for page in pages:
            PagePermission.objects.get_or_create(
                group=admin_group,
                page=page,
                defaults={
                    'can_read': True,
                    'can_write': True
                }
            )

        # Create superuser if not exists
        username = options.get('username') or 'admin'
        email = options.get('email') or 'admin@example.com'
        password = options.get('password') or 'admin123'

        if not User.objects.filter(username=username).exists():
            user = User.objects.create_superuser(
                username=username,
                email=email,
                password=password
            )
            user.groups.add(admin_group)
            self.stdout.write(self.style.SUCCESS(f'Successfully created superuser "{username}" with full permissions'))
        else:
            user = User.objects.get(username=username)
            user.groups.add(admin_group)
            self.stdout.write(self.style.SUCCESS(f'Updated existing user "{username}" with full permissions')) 