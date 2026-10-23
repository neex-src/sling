-- The HR database the HRDB connector writes to: a stand-in for the real one (DB2 at work).
CREATE TABLE employees (
  id          SERIAL PRIMARY KEY,
  username    VARCHAR(64)  NOT NULL UNIQUE,
  first_name  VARCHAR(64),
  last_name   VARCHAR(64),
  full_name   VARCHAR(128),
  email       VARCHAR(128),
  department  VARCHAR(32),
  updated_at  TIMESTAMP    NOT NULL DEFAULT now()
);
INSERT INTO employees (username, first_name, last_name, full_name, email, department)
VALUES ('greta', 'Greta', 'Nagy', 'Greta Nagy', 'greta@hr.test', 'FIN');
