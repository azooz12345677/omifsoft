NetworkMode - Deployment Notes

1) Recommended architecture
- Run the Flask app behind a reverse proxy (Caddy or Nginx).
- Use a process manager (systemd, supervisord, or docker) to run both the web process and the mail worker.

2) Example systemd unit
- See `deploy/networkmode.service` (edit WorkingDirectory and ExecStart to your paths).

3) Reverse proxy (Caddy)
- Caddyfile example in `deploy/Caddyfile` will auto-provision TLS.

4) Reverse proxy (Nginx)
- Use `deploy/nginx.conf` as starting point; enable TLS with certbot or your CA.

5) Secrets
- Export production secrets via environment variables (systemd `Environment=` or separate env file):
  - SECRET_KEY
  - ADMIN_TOKEN
  - ADMIN_PASSWORD
  - SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, SMTP_FROM

6) Mail worker
- Run `python mail_worker.py` as a separate service to process mail queue.

7) Starting for testing
- Install dependencies: `pip install -r requirements.txt`
- Run web server: `python run_server.py --host 127.0.0.1 --port 8000`
- Run mail worker in another terminal: `python mail_worker.py`

8) Security checklist
- Move secrets to env vars and do not commit `config.py` with real secrets.
- Use TLS in front of the app (Caddy recommended for small deployments).
- Configure firewall to expose only needed ports (80/443 via reverse proxy).
