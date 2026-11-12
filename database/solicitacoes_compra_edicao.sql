-- =====================================================================
-- Edição de solicitações de compra
-- Rode este script UMA VEZ no Supabase: SQL Editor → New query → Run
-- (depois de database/solicitacoes_compra.sql)
-- =====================================================================

-- ---------------------------------------------------------------------
-- Troca o motivo e os itens de uma solicitação PENDENTE numa única
-- transação. p_itens: [{"produto_id": 1, "quantidade": 10}, ...]
-- Retorna true se editou, false se a solicitação não existe ou não
-- está mais pendente.
-- ---------------------------------------------------------------------
create or replace function public.editar_solicitacao_compra(
    p_codigo bigint,
    p_motivo text,
    p_itens  jsonb
)
returns boolean
language plpgsql
security definer
set search_path = public
as $$
begin
    if p_itens is null or jsonb_array_length(p_itens) = 0 then
        raise exception 'A solicitação precisa de pelo menos um produto.';
    end if;

    update solicitacoes_compra
    set motivo = p_motivo
    where codigo = p_codigo
      and status = 'Pendente';

    if not found then
        return false;
    end if;

    delete from solicitacoes_compra_itens
    where solicitacao_codigo = p_codigo;

    insert into solicitacoes_compra_itens (solicitacao_codigo, produto_id, quantidade)
    select p_codigo,
           (item ->> 'produto_id')::bigint,
           (item ->> 'quantidade')::integer
    from jsonb_array_elements(p_itens) as item;

    return true;
end;
$$;

revoke execute on function public.editar_solicitacao_compra(bigint, text, jsonb) from public, anon, authenticated;
grant execute on function public.editar_solicitacao_compra(bigint, text, jsonb) to service_role;
