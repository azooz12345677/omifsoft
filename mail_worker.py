#!/usr/bin/env python3
"""Mail worker: runs the mail queue loop (reads `mail_queue` table and sends emails).

Run this as a separate service/process:
  python mail_worker.py
"""
import time
import os
import sys
HERE = os.path.dirname(__file__)
sys.path.insert(0, HERE)

from server import enqueue_mail, send_email, query_database, app


def mail_queue_worker():
    print('Mail worker starting...')
    while True:
        try:
            row = query_database('SELECT id, to_email, subject, body, attempts FROM mail_queue ORDER BY created ASC LIMIT 1', one=True)
            if not row:
                time.sleep(2)
                continue
            mid = row.get('id')
            to = row.get('to_email')
            subj = row.get('subject')
            body = row.get('body')
            attempts = int(row.get('attempts') or 0)
            ok = send_email(to, subj, body)
            if ok:
                query_database('DELETE FROM mail_queue WHERE id = ?', (mid,))
            else:
                attempts += 1
                query_database('UPDATE mail_queue SET attempts = ? WHERE id = ?', (attempts, mid))
                if attempts > 5:
                    query_database('DELETE FROM mail_queue WHERE id = ?', (mid,))
                else:
                    time.sleep(min(30, attempts * 5))
        except Exception:
            import traceback
            traceback.print_exc()
            time.sleep(5)


if __name__ == '__main__':
    mail_queue_worker()
