-- =====================================================================
-- Permissões separadas por usuário
-- Rode este script UMA VEZ no Supabase: SQL Editor → New query → Run
--
-- Cada usuário passa a ter uma permissão para cada área do sistema.
-- O administrador (ADMIN_EMAIL no .env) continua com acesso total e
-- não depende desta tabela.
-- =====================================================================

-- Garante a tabela (ela já existe com usuario_id e pode_movimentar_estoque)
create table if not exists public.permissoes_usuarios (
    usuario_id uuid primary key
);

alter table public.permissoes_usuarios
    add column if not exists pode_cadastrar_produtos          boolean not null default false,
    add column if not exists pode_movimentar_estoque          boolean not null default false,
    add column if not exists pode_criar_requisicao            boolean not null default false,
    add column if not exists pode_aprovar_requisicao          boolean not null default false,
    add column if not exists pode_criar_solicitacao_compra    boolean not null default false,
    add column if not exists pode_aprovar_solicitacao_compra  boolean not null default false,
    add column if not exists pode_gerenciar_permissoes        boolean not null default false;

alter table public.permissoes_usuarios enable row level security;


-- ---------------------------------------------------------------------
-- Migração: mantém o que cada usuário já podia fazer antes da mudança
--   - todos podiam cadastrar produtos, criar requisições e solicitações
--   - quem movimentava o estoque também aprovava solicitações de compra
--   - aprovar requisições e gerenciar permissões era só do administrador
-- ---------------------------------------------------------------------
insert into public.permissoes_usuarios (usuario_id)
select id from auth.users
on conflict (usuario_id) do nothing;

update public.permissoes_usuarios
set pode_cadastrar_produtos         = true,
    pode_criar_requisicao           = true,
    pode_criar_solicitacao_compra   = true,
    pode_aprovar_solicitacao_compra = pode_movimentar_estoque;
