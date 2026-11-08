import hashlib
import json
import sqlite3
import time
from contextlib import closing, contextmanager


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


class Store:
    def __init__(self, path):
        self.path = path
        with self.connect() as db:
            db.execute("PRAGMA journal_mode=WAL")
            version = db.execute("PRAGMA user_version").fetchone()[0]
            if version == 0:
                db.executescript("""
                BEGIN;
                CREATE TABLE jobs(id TEXT PRIMARY KEY, kind TEXT NOT NULL, mode TEXT NOT NULL,
                                  status TEXT NOT NULL, created REAL NOT NULL, spec TEXT NOT NULL);
                CREATE TABLE events(id INTEGER PRIMARY KEY AUTOINCREMENT, job TEXT NOT NULL REFERENCES jobs(id),
                                    type TEXT NOT NULL, at REAL NOT NULL, data TEXT NOT NULL);
                CREATE INDEX events_job_id ON events(job,id);
                PRAGMA user_version=1;
                COMMIT;
                """)
            elif version != 1:
                raise RuntimeError("Unsupported database schema")

    @contextmanager
    def connect(self):
        with closing(sqlite3.connect(self.path, timeout=1)) as db, db:
            db.row_factory = sqlite3.Row
            db.execute("PRAGMA foreign_keys=ON")
            yield db

    def emit(self, job, name, data, status=None):
        with self.connect() as db:
            db.execute("INSERT INTO events(job,type,at,data) VALUES(?,?,?,?)",
                       (job, name, time.time(), json.dumps(data)))
            if status:
                db.execute("UPDATE jobs SET status=? WHERE id=?", (status, job))

    def create(self, job, kind, mode, spec):
        with self.connect() as db:
            db.execute("INSERT INTO jobs VALUES(?,?,?,?,?,?)", (job, kind, mode, "running", time.time(), json.dumps(spec)))
            db.execute("INSERT INTO events(job,type,at,data) VALUES(?,?,?,?)",
                       (job, f"{kind}.created", time.time(), json.dumps({"mode": mode, "spec": spec})))

    def jobs(self, kind=None):
        with self.connect() as db:
            return [self.job_dict(row) for row in db.execute(
                "SELECT * FROM jobs WHERE (? IS NULL OR kind=?) ORDER BY created DESC", (kind, kind)
            )]

    @staticmethod
    def job_dict(row):
        return {**dict(row), "spec": json.loads(row["spec"])}

    def get(self, job):
        with self.connect() as db:
            row = db.execute("SELECT * FROM jobs WHERE id=?", (job,)).fetchone()
            return self.job_dict(row) if row else None

    def events(self, job, after=0):
        with self.connect() as db:
            return [{**dict(row), "data": json.loads(row["data"])} for row in db.execute(
                "SELECT * FROM events WHERE job=? AND id>? ORDER BY id", (job, after)
            )]
