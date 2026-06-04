
CREATE TABLE IF NOT EXISTS users
(
    id             SERIAL PRIMARY KEY,
    username       varchar(64)  not null,
    email          varchar(256) not null,
    password       varchar(256) not null,
    email_verified boolean      default false not null,
    created_at     timestamp    not null
);
comment on table users is 'stores data about users';