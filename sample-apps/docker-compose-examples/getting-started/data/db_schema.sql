create database IF NOT EXISTS appsensor;
use appsensor;

CREATE USER 'appsensor_user'@'%' IDENTIFIED BY 'appsensor_pass';
GRANT ALL ON appsensor.* TO 'appsensor_user'@'%';
FLUSH PRIVILEGES;

create table `users` (
	username varchar(50) not null primary key,
	password varchar(100) not null,
	enabled boolean not null
);

create table `authorities` (
	id bigint UNSIGNED NOT NULL AUTO_INCREMENT primary key,
	authority varchar(50) not null
);

create table `groups` (
	id bigint UNSIGNED NOT NULL AUTO_INCREMENT primary key,
	group_name varchar(50) not null
);

create table `group_authorities` (
	group_id bigint UNSIGNED not null,
	authority_id bigint UNSIGNED not null,
	constraint fk_group_authorities_group foreign key(group_id) references `groups`(id),
	constraint fk_group_authorities_authority foreign key(authority_id) references `authorities`(id)
);

create table `user_authorities` (
	username varchar(50) not null,
	authority_id bigint UNSIGNED not null,
	constraint fk_user_authorities_user foreign key(username) references `users`(username),
	constraint fk_user_authorities_authority foreign key(authority_id) references `authorities`(id)
);

create table `group_users` (
	username varchar(50) not null,
	group_id bigint UNSIGNED not null,
	constraint fk_group_users_user foreign key(username) references `users`(username),
	constraint fk_group_users_group foreign key(group_id) references `groups`(id)
);

create table `user_client_applications` (
	username varchar(50) not null,
	client_application_name varchar(150) not null,
	constraint fk_user_client_applications_user foreign key(username) references `users`(username)
);

INSERT INTO authorities (authority) VALUES ('USER_ADMINISTRATION');
INSERT INTO authorities (authority) VALUES ('VIEW_CONFIGURATION');
INSERT INTO authorities (authority) VALUES ('EDIT_CONFIGURATION');
INSERT INTO authorities (authority) VALUES ('VIEW_DATA');

INSERT INTO `groups` (group_name) VALUES ('ANALYST');
INSERT INTO `groups` (group_name) VALUES ('USER_ADMINISTRATOR');
INSERT INTO `groups` (group_name) VALUES ('SYSTEM_ADMINISTRATOR');

INSERT INTO group_authorities (group_id, authority_id) VALUES (
	(select id from `groups` where group_name = 'ANALYST'), 
	(select id from authorities where authority = 'VIEW_DATA'));
INSERT INTO group_authorities (group_id, authority_id) VALUES (
	(select id from `groups` where group_name = 'ANALYST'), 
	(select id from authorities where authority = 'VIEW_CONFIGURATION'));
INSERT INTO group_authorities (group_id, authority_id) VALUES (
	(select id from `groups` where group_name = 'SYSTEM_ADMINISTRATOR'), 
	(select id from authorities where authority = 'EDIT_CONFIGURATION'));
INSERT INTO group_authorities (group_id, authority_id) VALUES (
	(select id from `groups` where group_name = 'USER_ADMINISTRATOR'), 
	(select id from authorities where authority = 'USER_ADMINISTRATION'));

INSERT INTO users(username,password,enabled)
	VALUES ('analyst','$2a$12$z9oPf2Ri.mgvzAGFWWmoXeEXDag77m8DfNy1VA4NQ9BFtscjvhn5W', true);
INSERT INTO users(username,password,enabled)
	VALUES ('sysadmin','$2a$08$.TbURV4uFy6uGiJeFpgSV..jQD6rRb3dVyJpwOT1nZCt9xEZ2FlVG', true);
INSERT INTO users(username,password,enabled)
	VALUES ('useradmin','$2a$08$Hz6jVRLMAQUizeJJ7L3UVezVK2JfI1ZpAqDDi4pxI0pNSHHaQkTsi', true);
INSERT INTO users(username,password,enabled)
	VALUES ('uberuser','$2a$08$BbqN0KJ2yelUmQzGrK4/B.JkksjEahG.SWrmcqMTWdJJOdmTHJo.G', true);
INSERT INTO group_users (username, group_id) VALUES ('analyst', (select id from `groups` where group_name = 'ANALYST'));
INSERT INTO group_users (username, group_id) VALUES ('sysadmin', (select id from `groups` where group_name = 'SYSTEM_ADMINISTRATOR'));
INSERT INTO group_users (username, group_id) VALUES ('useradmin', (select id from `groups` where group_name = 'USER_ADMINISTRATOR'));
INSERT INTO group_users (username, group_id) VALUES ('uberuser', (select id from `groups` where group_name = 'ANALYST'));
INSERT INTO group_users (username, group_id) VALUES ('uberuser', (select id from `groups` where group_name = 'SYSTEM_ADMINISTRATOR'));
INSERT INTO group_users (username, group_id) VALUES ('uberuser', (select id from `groups` where group_name = 'USER_ADMINISTRATOR'));
INSERT INTO user_client_applications(username, client_application_name) VALUES ('analyst', 'myclientapp');
INSERT INTO user_client_applications(username, client_application_name) VALUES ('analyst', 'myclientgeoapp1');
INSERT INTO user_client_applications(username, client_application_name) VALUES ('analyst', 'myclientgeoapp2');
INSERT INTO user_client_applications(username, client_application_name) VALUES ('analyst', 'myclientgeoapp3');
INSERT INTO user_client_applications(username, client_application_name) VALUES ('sysadmin', 'myclientgeoapp2');
INSERT INTO user_client_applications(username, client_application_name) VALUES ('uberuser', 'myclientapp');
INSERT INTO user_client_applications(username, client_application_name) VALUES ('uberuser', 'myclientgeoapp1');
INSERT INTO user_client_applications(username, client_application_name) VALUES ('uberuser', 'myclientgeoapp2');
INSERT INTO user_client_applications(username, client_application_name) VALUES ('uberuser', 'myclientgeoapp3');
INSERT INTO user_client_applications(username, client_application_name) VALUES ('uberuser', 'myclientgeoapp4');

