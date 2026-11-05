-- =====================================================================
-- Solicitações de compra
-- Rode este script UMA VEZ no Supabase: SQL Editor → New query → Run
-- =====================================================================

-- Cabeçalho da solicitação. O "codigo" é gerado automaticamente em
-- sequência pelo banco (1, 2, 3...), sem risco de números repetidos.
create table if not exists public.solicitacoes_compra (
    codigo              bigint generated always as identity primary key,
    motivo              text        not null check (char_length(motivo) between 1 and 1000),
    status              text        not null default 'Pendente'
                        check (status in ('Pendente', 'Comprada', 'Recebida', 'Rejeitada')),

    solicitante_id      uuid        not null,
    solicitante_email   text        not null,
    data_solicitacao    timestamptz not null default now(),

    -- Preenchidos quando a solicitação é aprovada ou rejeitada
    aprovador_email     text,
    data_decisao        timestamptz,
    motivo_rejeicao     text,

    -- Preenchidos quando os produtos chegam
    recebedor_email     text,
    data_recebimento    timestamptz
);

-- Produtos de cada solicitação (uma solicitação pode ter vários produtos)
create table if not exists public.solicitacoes_compra_itens (
    id                  bigint generated always as identity primary key,
    solicitacao_codigo  bigint not null references public.solicitacoes_compra (codigo) on delete cascade,
    produto_id          bigint not null references public.produtos (id),
    quantidade          integer not null check (quantidade > 0)
);

create index if not exists idx_solicitacoes_compra_status
    on public.solicitacoes_compra (status);

create index if not exists idx_solicitacoes_compra_data
    on public.solicitacoes_compra (data_solicitacao desc);

create index if not exists idx_solicitacoes_compra_itens_solicitacao
    on public.solicitacoes_compra_itens (solicitacao_codigo);

-- RLS ligado e sem políticas: só o servidor (chave secreta) acessa.
alter table public.solicitacoes_compra enable row level security;
alter table public.solicitacoes_compra_itens enable row level security;


-- ---------------------------------------------------------------------
-- Cria a solicitação e seus itens numa única transação.
-- p_itens: [{"produto_id": 1, "quantidade": 10}, ...]
-- Retorna o código gerado.
-- ---------------------------------------------------------------------
create or replace function public.criar_solicitacao_compra(
    p_solicitante_id    uuid,
    p_solicitante_email text,
    p_motivo            text,
    p_itens             jsonb
)
returns bigint
language plpgsql
security definer
set search_path = public
as $$
declare
    v_codigo bigint;
begin
    if p_itens is null or jsonb_array_length(p_itens) = 0 then
        raise exception 'A solicitação precisa de pelo menos um produto.';
    end if;

    insert into solicitacoes_compra (solicitante_id, solicitante_email, motivo)
    values (p_solicitante_id, p_solicitante_email, p_motivo)
    returning codigo into v_codigo;

    insert into solicitacoes_compra_itens (solicitacao_codigo, produto_id, quantidade)
    select v_codigo,
           (item ->> 'produto_id')::bigint,
           (item ->> 'quantidade')::integer
    from jsonb_array_elements(p_itens) as item;

    return v_codigo;
end;
$$;


-- ---------------------------------------------------------------------
-- Marca a solicitação como recebida e dá ENTRADA no estoque de cada
-- produto, registrando no histórico de movimentações. Tudo ou nada.
-- ---------------------------------------------------------------------
create or replace function public.receber_solicitacao_compra(
    p_codigo      bigint,
    p_responsavel text
)
returns void
language plpgsql
security definer
set search_path = public
as $$
declare
    v_status text;
    v_item   record;
begin
    select status into v_status
    from solicitacoes_compra
    where codigo = p_codigo
    for update;

    if v_status is null then
        raise exception 'Solicitação % não encontrada.', p_codigo;
    end if;

    if v_status <> 'Comprada' then
        raise exception 'Somente solicitações com status Comprada podem ser recebidas.';
    end if;

    for v_item in
        select produto_id, quantidade
        from solicitacoes_compra_itens
        where solicitacao_codigo = p_codigo
    loop
        update produtos
        set quantidade = quantidade + v_item.quantidade
        where id = v_item.produto_id;

        insert into movimentacoes (produto_id, tipo, quantidade)
        values (v_item.produto_id, 'Entrada', v_item.quantidade);
    end loop;

    update solicitacoes_compra
    set status = 'Recebida',
        recebedor_email = p_responsavel,
        data_recebimento = now()
    where codigo = p_codigo;
end;
$$;

-- As funções só podem ser chamadas pelo servidor
revoke execute on function public.criar_solicitacao_compra(uuid, text, text, jsonb) from public, anon, authenticated;
revoke execute on function public.receber_solicitacao_compra(bigint, text) from public, anon, authenticated;
grant execute on function public.criar_solicitacao_compra(uuid, text, text, jsonb) to service_role;
grant execute on function public.receber_solicitacao_compra(bigint, text) to service_role;
