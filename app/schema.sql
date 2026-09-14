-- Esquema DDL para Proyecto de Seguridad Informática
-- PostgreSQL Puro (sin ORM)

CREATE TABLE IF NOT EXISTS usuarios (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    rol VARCHAR(50) NOT NULL DEFAULT 'usuario' CHECK (rol IN ('usuario', 'administrador')),
    fecha_registro TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Índice para acelerar búsquedas seguras por email
CREATE INDEX IF NOT EXISTS idx_usuarios_email ON usuarios(email);
