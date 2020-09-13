CREATE TABLE users (
  id SERIAL PRIMARY KEY,
  typetalk_user_id VARCHAR(255) UNIQUE NOT NULL
);

CREATE TABLE oauth2 (
  id SERIAL PRIMARY KEY,
  user_id integer,
  access_token VARCHAR(255) NOT NULL,
  refresh_token VARCHAR(255) NOT NULL,
  token_type VARCHAR(255),
  expire_time TIMESTAMP NOT NULL,
  provider VARCHAR(20),
  created_at TIMESTAMP NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);

ALTER TABLE oauth2
ADD CONSTRAINT oauth2_unique UNIQUE (user_id, provider);

ALTER TABLE oauth2 
   ADD CONSTRAINT fk_user_id
   FOREIGN KEY (user_id) 
   REFERENCES users(id);