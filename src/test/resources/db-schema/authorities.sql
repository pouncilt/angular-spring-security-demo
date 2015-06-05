CREATE TABLE appsec.authorities
(
    username VARCHAR(250) NOT NULL,
    authority VARCHAR(50) NOT NULL,
    CONSTRAINT fk_authorities_users FOREIGN KEY (username) REFERENCES users(username),
    UNIQUE INDEX auth_username_idx (username,authority)
) engine = InnoDb;