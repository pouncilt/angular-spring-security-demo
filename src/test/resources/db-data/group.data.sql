insert into appsec.groups (group_name) values ('Admin');
insert into appsec.group_authorities (group_id, authority) values (1, 'Reset Password');
insert into appsec.group_members (username, group_id) values ('pouncilt', 1);