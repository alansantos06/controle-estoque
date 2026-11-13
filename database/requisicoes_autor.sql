-- =====================================================================
-- Autor das requisições
-- Rode este script UMA VEZ no Supabase: SQL Editor → New query → Run
--
-- Guarda qual usuário criou cada requisição, para que ele possa editar
-- ou excluir as próprias requisições pendentes. As requisições antigas
-- ficam sem autor: só quem pode aprovar requisições consegue alterá-las.
-- =====================================================================

alter table public.requisicoes
    add column if not exists criado_por_id    uuid,
    add column if not exists criado_por_email text;

create index if not exists idx_requisicoes_criado_por
    on public.requisicoes (criado_por_id);
