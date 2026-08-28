-- LAB ONLY — intentionally permissive seed data for the isolated cyber range.
CREATE TABLE IF NOT EXISTS customers (
    id SERIAL PRIMARY KEY,
    email TEXT NOT NULL,
    full_name TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'customer',
    password_hash TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS orders (
    id SERIAL PRIMARY KEY,
    customer_id INT NOT NULL REFERENCES customers(id),
    product TEXT NOT NULL,
    amount NUMERIC NOT NULL,
    card_tail TEXT NOT NULL
);

-- Documented lab weakness: plaintext storage + a default admin password.
INSERT INTO customers (email, full_name, role, password_hash) VALUES
    ('alice@lab.local',  'Alice Anderson', 'customer', 'alice'),
    ('bob@lab.local',    'Bob Brown',      'customer', 'bob'),
    ('carol@lab.local',  'Carol Chen',     'customer', 'carol'),
    ('dave@lab.local',   'Dave Davis',     'customer', 'dave'),
    ('admin@lab.local',  'Lab Admin',      'admin',    'admin')
ON CONFLICT DO NOTHING;

INSERT INTO orders (customer_id, product, amount, card_tail) VALUES
    (1, 'Laptop',      1299, '4242'),
    (2, 'Monitor',      349, '1111'),
    (3, 'Server Rack', 8999, '0001'),
    (4, 'GPU',         1599, '7777'),
    (1, 'NAS',          599, '4242')
ON CONFLICT DO NOTHING;
