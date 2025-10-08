#!/usr/bin/env python3
"""Run helper for NetworkMode app.

Usage:
  python run_server.py --host example.com --port 8000 [--cert cert.pem --key key.pem] [--workers 2]

The script will try to use hypercorn, then gunicorn, then waitress, and finally fall back to the Flask dev server.
It reads environment variables as defaults: NM_HOST, NM_PORT, NM_CERT, NM_KEY, NM_WORKERS.
"""
import os
import sys
import argparse
import shutil
import subprocess

HERE = os.path.dirname(__file__)
sys.path.insert(0, HERE)

def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument('--host', default=os.environ.get('NM_HOST', '127.0.0.1'))
    p.add_argument('--port', type=int, default=int(os.environ.get('NM_PORT', '8000')))
    p.add_argument('--cert', default=os.environ.get('NM_CERT'))
    p.add_argument('--key', default=os.environ.get('NM_KEY'))
    p.add_argument('--workers', type=int, default=int(os.environ.get('NM_WORKERS', '2')))
    p.add_argument('--debug', action='store_true')
    return p.parse_args()


def which(bin_name):
    return shutil.which(bin_name)


def run_hypercorn(host, port, cert, key, workers, debug):
    try:
        import hypercorn
    except Exception:
        return False
    cmd = [sys.executable, '-m', 'hypercorn', 'server:app', '--bind', f'{host}:{port}']
    if cert and key:
        cmd += ['--certfile', cert, '--keyfile', key]
    if workers:
        cmd += ['--workers', str(workers)]
    if debug:
        cmd += ['--reload']
    print('Launching with hypercorn:',' '.join(cmd))
    os.execv(sys.executable, cmd)


def run_gunicorn(host, port, cert, key, workers, debug):
    # prefer gunicorn if available
    if not which('gunicorn'):
        return False
    bind = f'{host}:{port}'
    cmd = ['gunicorn', 'server:app', '--bind', bind, '--workers', str(workers)]
    if cert and key:
        # gunicorn does not directly take certfile/keyfile; recommend running behind TLS proxy; still allow --certfile for some setups
        cmd += ['--certfile', cert, '--keyfile', key]
    if debug:
        cmd += ['--reload']
    print('Launching with gunicorn:', ' '.join(cmd))
    os.execvp('gunicorn', cmd)


def run_waitress(host, port, cert, key, workers, debug):
    try:
        from waitress import serve
    except Exception:
        return False
    print(f'Starting waitress HTTP server on {host}:{port} (no TLS)')
    # Waitress does not handle TLS directly; recommend using a TLS reverse proxy
    from server import app
    serve(app, host=host, port=port, threads=workers)


def run_dev(host, port, cert, key, workers, debug):
    print('Falling back to Flask dev server (not for production).')
    from server import app
    app.run(host=host, port=port, debug=debug)


def main():
    args = parse_args()
    host = args.host
    port = args.port
    cert = args.cert
    key = args.key
    workers = args.workers
    debug = args.debug

    # try hypercorn (preferred)
    if run_hypercorn(host, port, cert, key, workers, debug):
        return
    # try gunicorn
    if run_gunicorn(host, port, cert, key, workers, debug):
        return
    # try waitress
    if run_waitress(host, port, cert, key, workers, debug):
        return
    # fallback
    run_dev(host, port, cert, key, workers, debug)


if __name__ == '__main__':
    main()
