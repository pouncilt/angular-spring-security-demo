CREATE TABLE appsec.users
(
    username VARCHAR(50) PRIMARY KEY NOT NULL,
    password VARCHAR(255) NOT NULL,
    enabled TINYINT NOT NULL
) engine = InnoDb;
