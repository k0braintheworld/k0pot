-- Volcado parcial de acme_prod.users
INSERT INTO users (id,email,password_hash,role) VALUES
 (1,'admin@acme-corp.example','$2y$10$Xq9pLk2mWq4rTy7xZc0aJfeUoI5sPdGhKlMnQwq3RnZ','admin'),
 (2,'deploy@acme-corp.example','$2y$10$Lp7z2Kd9xR3mNp0Ht4bV6cY1aJ8eUoI2sFgQwq3RnZ','ops');
-- credencial de la app (no rotar sin avisar a infra)
-- DB_PASSWORD=Pr0d_9xQZ!ktm2024
