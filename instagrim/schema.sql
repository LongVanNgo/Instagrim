drop table if exists users;
create table users (
    'id' INTEGER primary key,
    'username' TEXT not null,
    'password' TEXT not null
);

drop table if exists posts;
create table posts (
    'id' INTEGER primary key,
    'user_id' INTEGER not null,
    'created' TEXT not null,
    'message' TEXT not null,
    'image' TEXT not null
);
