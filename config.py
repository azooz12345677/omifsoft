# Local configuration - DO NOT COMMIT
# This file enables SMTP email sending for verification codes.
# Adjust values as needed. Keep this file private.

SECRET_KEY = 'change-me-to-a-secure-random-string'

# SMTP settings (example: Gmail SMTP using an App Password)
SMTP_HOST = 'smtp.gmail.com'
SMTP_PORT = 587
SMTP_USER = 'alrazwmali@gmail.com'
SMTP_PASS = 'qcwgdxcnrefjloiw'
SMTP_FROM = 'Network Mode <alrazwmali@gmail.com>'

# Admin username used for admin-only access
ADMIN_USERNAME = 'admin azooz'
# Admin token removed for safety. Token-based admin access is disabled in the server.
ADMIN_TOKEN = None
ADMIN_SHOW_PLAINTEXT_PASSWORDS = True