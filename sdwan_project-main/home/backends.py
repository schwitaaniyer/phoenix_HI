from django.contrib.auth.backends import ModelBackend
from django_auth_ldap.backend import LDAPBackend
import ldap
import logging

logger = logging.getLogger(__name__)

class LDAPFallbackBackend:
    def authenticate(self, request, username=None, password=None, **kwargs):
        ldap_backend = LDAPBackend()

        try:
            # Attempt LDAP authentication
            user = ldap_backend.authenticate(request, username=username, password=password, **kwargs)
            if user:
                logger.info("User authenticated via LDAP.")
                return user
        except ldap.SERVER_DOWN:
            logger.warning("LDAP server is down. Falling back to Django ModelBackend.")
        except ldap.LDAPError as e:
            logger.error(f"LDAP error: {e}")

        # Fallback to Django's ModelBackend if LDAP authentication fails
        user = ModelBackend().authenticate(request, username=username, password=password, **kwargs)
        if user:
            logger.info("User authenticated via Django ModelBackend.")
        return user

    def get_user(self, user_id):
        return ModelBackend().get_user(user_id)
