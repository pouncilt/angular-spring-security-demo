create table appsec.groups (
  id BIGINT UNSIGNED PRIMARY KEY NOT NULL AUTO_INCREMENT,
  group_name varchar(50) not null
) engine = InnoDb;
/*ALTER TABLE appsec.groups AUTO_INCREMENT = 0;*/

create table appsec.group_authorities (
  group_id bigint UNSIGNED PRIMARY KEY not null,
  authority varchar(50) not null,
  constraint fk_group_authorities_group foreign key(group_id) references groups(id)
) engine = InnoDb;
/*ALTER TABLE appsec.groups AUTO_INCREMENT = 0;*/

create table appsec.group_members (
  id BIGINT UNSIGNED PRIMARY KEY NOT NULL AUTO_INCREMENT,
  username varchar(50) not null,
  group_id bigint UNSIGNED not null,
  constraint fk_group_members_group foreign key(group_id) references groups(id)
) engine = InnoDb;
/*ALTER TABLE appsec.group_members AUTO_INCREMENT = 0;*/
