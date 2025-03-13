from django.apps import AppConfig


class AuthSystemConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'auth_system'



class AuthSystemConfig(AppConfig):
    name = 'auth_system'

    def ready(self):
        import auth_system.signals  