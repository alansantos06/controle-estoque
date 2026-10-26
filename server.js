const express = require('express');
const session = require('express-session');
const { csrfSync } = require('csrf-sync');

const {
    supabase,
    supabaseAuth,
    supabaseAdmin
} = require('./supabase');

const app = express();

app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        secure: false,
        sameSite: 'lax',
        maxAge: 1000 * 60 * 60 * 8
    }
}));

const {
    generateToken,
    csrfSynchronisedProtection
} = csrfSync({
    getTokenFromRequest: (req) => req.body?._csrf
});

app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

app.use(csrfSynchronisedProtection);

app.use((req, res, next) => {
    res.locals.csrfToken = generateToken(req);
    next();
});
const PORT = 3000;


 // Verificar se o usuário está autenticado
function exigirLogin(req, res, next) {
    if (req.session && req.session.usuario) {
        return next();
    }

    return res.redirect('/login');
}


function exigirAdministrador(req, res, next) {
    const emailUsuario = req.session?.usuario?.email
        ?.trim()
        .toLowerCase();

    const emailAdministrador = process.env.ADMIN_EMAIL
        ?.trim()
        .toLowerCase();

    if (!emailUsuario) {
        return res.redirect('/login');
    }

    if (
        !emailAdministrador ||
        emailUsuario !== emailAdministrador
    ) {
        return res.status(403).send(
            'Acesso negado. Somente o administrador pode realizar esta ação.'
        );
    }

    return next();
}


// Proteger as páginas e operações do sistema
app.use((req, res, next) => {
    const rotasPublicas = ['/login'];

    if (rotasPublicas.includes(req.path)) {
        return next();
    }

    return exigirLogin(req, res, next);
});


// Configuração do EJS
app.set('view engine', 'ejs');

// Página inicial


 // Página de login
app.get('/login', (req, res) => {
    if (req.session.usuario) {
        return res.redirect('/');
    }

    res.render('login', { erro: '' });
});

// Processar login
app.post('/login', async (req, res) => {
    try {
        const email = String(req.body.email || '').trim();
        const senha = String(req.body.senha || '');

        if (!email || !senha) {
            return res.status(400).render('login', {
                erro: 'Informe o e-mail e a senha.'
            });
        }

        const { data, error } = await supabaseAuth.auth.signInWithPassword({
            email,
            password: senha
        });

        if (error || !data.user) {
            return res.status(401).render('login', {
                erro: 'E-mail ou senha incorretos.'
            });
        }

        req.session.regenerate((erroSessao) => {
            if (erroSessao) {
                console.error('Erro ao criar sessão:', erroSessao);
                return res.status(500).render('login', {
                    erro: 'Não foi possível iniciar a sessão.'
                });
            }

            req.session.usuario = {
                id: data.user.id,
                email: data.user.email
            };

            req.session.save((erroSalvar) => {
                if (erroSalvar) {
                    console.error('Erro ao salvar sessão:', erroSalvar);
                    return res.status(500).render('login', {
                        erro: 'Não foi possível salvar a sessão.'
                    });
                }

                return res.redirect('/');
            });
        });
    } catch (erro) {
        console.error('Erro no login:', erro);
        return res.status(500).render('login', {
            erro: 'Ocorreu um erro ao tentar entrar.'
        });
    }
});

// Sair do sistema
app.post('/logout', (req, res) => {
    req.session.destroy((erro) => {
        if (erro) {
            console.error('Erro ao encerrar sessão:', erro);
            return res.status(500).send('Erro ao sair do sistema.');
        }

        res.clearCookie('connect.sid');
        return res.redirect('/login');
    });
});


app.get('/', async (req, res) => {
    const { data: produtos, error } = await supabase
        .from('produtos')
        .select('*');

    if (error) {
        console.error(error);
        return res.status(500).send('Erro ao consultar os produtos');
    }

    const totalProdutos = produtos.length;

    const totalEstoque = produtos.reduce(
        (total, produto) => total + produto.quantidade,
        0
    );

    const produtosEstoqueBaixo = produtos.filter(
        produto => produto.quantidade <= produto.estoque_minimo
    );

    res.render('inicio', {
        produtos,
        totalProdutos,
        totalEstoque,
        produtosEstoqueBaixo
    });
});


// Página de cadastro de novo produto
app.get('/produtos/novo', (req, res) => {
    res.render('novo-produto', {
        erro: req.query.erro || ''
    });
});

// Página de edição de produto
app.get('/produtos/:id/editar', async (req, res) => {

    const { id } = req.params;

    const { data: produto, error } = await supabase
        .from('produtos')
        .select('*')
        .eq('id', id)
        .single();

    if (error) {
        console.error(error);
        return res.status(500).send('Erro ao buscar produto');
    }

    res.render('editar-produto', {
        produto,
        erro: req.query.erro || ''
    });
});

// Atualizar produto
app.post('/produtos/:id/editar', async (req, res) => {

    const { id } = req.params;

    const {
        nome,
        estoque_minimo,
        estoque_maximo
    } = req.body;

    // Verifica se o nome foi preenchido
    if (!nome || nome.trim() === '') {
        return res.redirect(`/produtos/${id}/editar?erro=nome`);
    }

    // Converte os valores para números
    const minimoNumero = Number(estoque_minimo);
    const maximoNumero = Number(estoque_maximo);

    // Verifica se os valores são números válidos
    if (isNaN(minimoNumero) || isNaN(maximoNumero)) {
        return res.redirect(`/produtos/${id}/editar?erro=numeros`);
    }

    // Verifica se algum valor é negativo
    if (minimoNumero < 0 || maximoNumero < 0) {
        return res.redirect(`/produtos/${id}/editar?erro=negativo`);
    }

    // Verifica se o máximo é maior ou igual ao mínimo
    if (maximoNumero < minimoNumero) {
        return res.redirect(`/produtos/${id}/editar?erro=limites`);
    }

    // Atualiza o produto no Supabase
    const { error } = await supabase
        .from('produtos')
        .update({
            nome: nome.trim(),
            estoque_minimo: minimoNumero,
            estoque_maximo: maximoNumero
        })
        .eq('id', id);

    if (error) {
        console.error(error);
        return res.redirect(`/produtos/${id}/editar?erro=servidor`);
    }

    // Volta para a lista de produtos
    res.redirect('/produtos?mensagem=editado');
});

// Cadastrar novo produto
app.post('/produtos', async (req, res) => {

    const {
        nome,
        quantidade,
        estoque_minimo,
        estoque_maximo
    } = req.body;

    // Verifica se o nome foi preenchido
    if (!nome || nome.trim() === '') {
        return res.redirect('/produtos/novo?erro=nome');
    }

    // Converte os valores para números
    const quantidadeNumero = Number(quantidade);
    const minimoNumero = Number(estoque_minimo);
    const maximoNumero = Number(estoque_maximo);

    // Verifica se os números são válidos
    if (
        isNaN(quantidadeNumero) ||
        isNaN(minimoNumero) ||
        isNaN(maximoNumero)
    ) {
        return res.status(400).send('Os valores de estoque devem ser números.');
    }

    // Verifica se algum valor é negativo
    if (
        quantidadeNumero < 0 ||
        minimoNumero < 0 ||
        maximoNumero < 0
    ) {
        return res.status(400).send('Os valores de estoque não podem ser negativos.');
    }

  

    if (maximoNumero < minimoNumero) {
        return res.redirect('/produtos/novo?erro=limites');
    }

    // Cadastra o produto no Supabase
    const { data, error } = await supabase
        .from('produtos')
        .insert([
            {
                nome: nome.trim(),
                quantidade: quantidadeNumero,
                estoque_minimo: minimoNumero,
                estoque_maximo: maximoNumero
            }
        ]);

    if (error) {
        console.log('ERRO DO SUPABASE:');
        console.log(error);

        return res.redirect('/produtos/novo?erro=servidor');
    }
    
 // Volta para a lista de produtos exibindo uma mensagem
    res.redirect('/produtos?mensagem=cadastrado');

});

// Página de produtos

app.get('/produtos', async (req, res) => {
    const { busca, estoqueBaixo, mensagem, erro } = req.query;

    let consulta = supabase
        .from('produtos')
        .select('*')
        .order('id', { ascending: true });

    if (busca && busca.trim() !== '') {
        const textoBusca = busca.trim();

        const numeroCodigo = textoBusca.replace(/^MAT/i, '');

        if (!isNaN(Number(numeroCodigo)) && numeroCodigo !== '') {
            consulta = consulta.eq('id', Number(numeroCodigo));
        } else {
            consulta = consulta.ilike('nome', `%${textoBusca}%`);
        }
    }

    const { data: todosProdutos, error } = await consulta;

    if (error) {
        console.error(error);
        return res.status(500).send('Erro ao consultar os produtos');
    }

    let produtos = todosProdutos;

    if (estoqueBaixo === 'sim') {
        produtos = todosProdutos.filter(
            produto => produto.quantidade <= produto.estoque_minimo
        );
    }

    res.render('produtos', {
        produtos,
        busca: busca || '',
        estoqueBaixo: estoqueBaixo || 'nao',
        mensagem: mensagem || '',
        erro: erro || ''
    });
});



 // Excluir produto
app.post('/produtos/:id/excluir', async (req, res) => {

    const { id } = req.params;

    // Verifica se o produto possui movimentações
    const { data: movimentacoes, error: erroMovimentacoes } = await supabase
        .from('movimentacoes')
        .select('id')
        .eq('produto_id', id);

    if (erroMovimentacoes) {
        console.error(erroMovimentacoes);
        return res.redirect('/produtos?erro=excluir');
    }

    // Não permite excluir produto que possui movimentações
    if (movimentacoes && movimentacoes.length > 0) {
        return res.redirect('/produtos?erro=possuiMovimentacoes');
    }

    // Exclui o produto
    const { error } = await supabase
        .from('produtos')
        .delete()
        .eq('id', id);

    if (error) {
        console.error(error);
        return res.redirect('/produtos?erro=excluir');
    }

    // Confirma a exclusão
    res.redirect('/produtos?mensagem=excluido');
});



app.get('/requisicoes', async (req, res) => {
    try {
        const { data: requisicoes, error: erroRequisicoes } = await supabase
            .from('requisicoes')
            .select(`
                *,
                produtos (
                    id,
                    nome,
                    quantidade
                )
            `)
            .order('data_solicitacao', { ascending: false });

        if (erroRequisicoes) {
            throw erroRequisicoes;
        }

        const { data: produtos, error: erroProdutos } = await supabase
            .from('produtos')
            .select('id, nome, quantidade')
            .order('nome', { ascending: true });

        if (erroProdutos) {
            throw erroProdutos;
        }

        res.render('requisicoes', {
            requisicoes: requisicoes || [],
            produtos: produtos || [],
            mensagem: req.query.mensagem || '',
            erro: req.query.erro || ''
        });
    } catch (erro) {
        console.error('Erro ao carregar requisições:', erro);
        res.status(500).send('Erro ao carregar as requisições.');
    }
});



/* Criar uma nova requisição */
app.post('/requisicoes', async (req, res) => {
    try {
        const produtoId = Number(req.body.produto_id);
        const quantidade = Number(req.body.quantidade);
        const solicitante = String(req.body.solicitante || '').trim();
        const observacao = String(req.body.observacao || '').trim();

        if (
            !Number.isSafeInteger(produtoId) ||
            produtoId <= 0 ||
            !Number.isSafeInteger(quantidade) ||
            quantidade <= 0 ||
            !solicitante ||
            solicitante.length > 150 ||
            observacao.length > 1000
        ) {
            return res.redirect(
                '/requisicoes?erro=' +
                encodeURIComponent('Preencha os campos corretamente.')
            );
        }

        const { data: produto, error: erroProduto } = await supabase
            .from('produtos')
            .select('id')
            .eq('id', produtoId)
            .maybeSingle();

        if (erroProduto) throw erroProduto;

        if (!produto) {
            return res.redirect(
                '/requisicoes?erro=' +
                encodeURIComponent('O produto selecionado não existe.')
            );
        }

        const { error } = await supabase
            .from('requisicoes')
            .insert({
                produto_id: produtoId,
                quantidade,
                solicitante,
                observacao: observacao || null
            });

        if (error) throw error;

        return res.redirect(
            '/requisicoes?mensagem=' +
            encodeURIComponent('Requisição enviada com sucesso!')
        );
    } catch (erro) {
        console.error('Erro ao criar requisição:', erro);

        return res.redirect(
            '/requisicoes?erro=' +
            encodeURIComponent('Não foi possível criar a requisição.')
        );
    }
});


/* Aprovar uma requisição e descontar o estoque */
app.post(
    '/requisicoes/:id/aprovar',
    exigirAdministrador,
    async (req, res) => {
    try {
        const requisicaoId = Number(req.params.id);

        if (!Number.isSafeInteger(requisicaoId) || requisicaoId <= 0) {
            return res.redirect(
                '/requisicoes?erro=' +
                encodeURIComponent('ID de requisição inválido.')
            );
        }

        const { error } = await supabaseAdmin.rpc('aprovar_requisicao', {
            p_requisicao_id: requisicaoId,
            p_responsavel: req.session.usuario.email
        });

        if (error) {
            console.error('Erro ao aprovar requisição:', error);

            return res.redirect(
                '/requisicoes?erro=' +
                encodeURIComponent(error.message)
            );
        }

        return res.redirect(
            '/requisicoes?mensagem=' +
            encodeURIComponent('Requisição aprovada e estoque atualizado!')
        );
    } catch (erro) {
        console.error('Erro ao aprovar requisição:', erro);

        return res.redirect(
            '/requisicoes?erro=' +
            encodeURIComponent('Não foi possível aprovar a requisição.')
        );
    }
});


/* Rejeitar uma requisição sem alterar o estoque */
app.post(
    '/requisicoes/:id/rejeitar',
    exigirAdministrador,
    async (req, res) => {
    try {
        const requisicaoId = Number(req.params.id);
        const motivo = String(req.body.motivo_rejeicao || '').trim();

        if (
            !Number.isSafeInteger(requisicaoId) ||
            requisicaoId <= 0 ||
            !motivo ||
            motivo.length > 1000
        ) {
            return res.redirect(
                '/requisicoes?erro=' +
                encodeURIComponent('Informe um ID válido e o motivo da rejeição.')
            );
        }

        const { data, error } = await supabaseAdmin
            .from('requisicoes')
            .update({
                status: 'Rejeitada',
                data_decisao: new Date().toISOString(),
                responsavel_decisao: req.session.usuario.email,
                motivo_rejeicao: motivo
            })
            .eq('id', requisicaoId)
            .eq('status', 'Pendente')
            .select('id')
            .maybeSingle();

        if (error) throw error;

        if (!data) {
            return res.redirect(
                '/requisicoes?erro=' +
                encodeURIComponent(
                    'Requisição não encontrada ou já decidida.'
                )
            );
        }

        return res.redirect(
            '/requisicoes?mensagem=' +

            encodeURIComponent('Requisição rejeitada. O estoque não foi alterado.')
        );
    } catch (erro) {
        console.error('Erro ao rejeitar requisição:', erro);

        return res.redirect(
            '/requisicoes?erro=' +
            encodeURIComponent('Não foi possível rejeitar a requisição.')
        );
    }
});




app.get('/movimentacoes', async (req, res) => {
    const { tipo } = req.query;

    let consulta = supabase
        .from('movimentacoes')
        .select(`
            id,
            tipo,
            quantidade,
            data,
            produtos (
                id,
                nome
            )
        `)
        .order('data', { ascending: false });

    if (tipo === 'Entrada' || tipo === 'Saída') {
        consulta = consulta.eq('tipo', tipo);
    }

    const { data: movimentacoes, error } = await consulta;

    if (error) {
        console.error(error);
        return res.status(500).send('Erro ao consultar o histórico');
    }

    res.render('historico', {
        movimentacoes,
        tipoSelecionado: tipo || 'Todos'
    });
});


app.get('/relatorios', async (req, res) => {
    const { dataInicio, dataFim } = req.query;

    let consulta = supabase
        .from('movimentacoes')
        .select(`
            id,
            tipo,
            quantidade,
            data,
            produtos (
                id,
                nome
            )
        `)
        .order('data', { ascending: false });

    // Filtrar pela data inicial
    if (dataInicio && /^\d{4}-\d{2}-\d{2}$/.test(dataInicio)) {
        consulta = consulta.gte('data', `${dataInicio}T00:00:00`);
    }

    // Filtrar pela data final
    if (dataFim && /^\d{4}-\d{2}-\d{2}$/.test(dataFim)) {
        consulta = consulta.lte('data', `${dataFim}T23:59:59.999`);
    }

    const { data: movimentacoes, error } = await consulta;

    if (error) {
        console.error('Erro ao consultar relatório:', error);
        return res.status(500).send('Erro ao gerar relatório');
    }

    const { data: produtos, error: erroProdutos } = await supabase
        .from('produtos')
        .select('id, nome, quantidade, estoque_minimo');

    if (erroProdutos) {
        console.error('Erro ao consultar produtos:', erroProdutos);
        return res.status(500).send('Erro ao consultar produtos');
    }

    const totalEntradas = movimentacoes
        .filter(m => m.tipo === 'Entrada')
        .reduce((total, m) => total + m.quantidade, 0);

    const totalSaidas = movimentacoes
        .filter(m => m.tipo === 'Saída')
        .reduce((total, m) => total + m.quantidade, 0);

    const ranking = {};

    movimentacoes.forEach(m => {
        const id = m.produtos?.id;
        if (!id) return;

        if (!ranking[id]) {
            ranking[id] = {
                id,
                nome: m.produtos.nome,
                entradas: 0,
                saidas: 0,
                totalMovimentado: 0
            };
        }

        if (m.tipo === 'Entrada') {
            ranking[id].entradas += m.quantidade;
        } else if (m.tipo === 'Saída') {
            ranking[id].saidas += m.quantidade;
        }

        ranking[id].totalMovimentado += m.quantidade;
    });

    const produtosRanking = Object.values(ranking)
        .sort((a, b) => b.totalMovimentado - a.totalMovimentado);

    
    // Agrupar as movimentações por mês
    const agrupamentoMensal = {};

    movimentacoes.forEach(m => {
        if (!m.data) return;

        // Usa o ano e o mês da data registrada no banco
        const data = String(m.data);
        const mes = data.substring(0, 7); // Exemplo: 2026-10

        if (!/^\d{4}-\d{2}$/.test(mes)) return;

        if (!agrupamentoMensal[mes]) {
            agrupamentoMensal[mes] = {
                mes,
                entradas: 0,
                saidas: 0
            };
        }

        if (m.tipo === 'Entrada') {
            agrupamentoMensal[mes].entradas += Number(m.quantidade) || 0;
        } else if (m.tipo === 'Saída') {
            agrupamentoMensal[mes].saidas += Number(m.quantidade) || 0;
        }
    });

    const movimentacoesPorMes = Object.values(agrupamentoMensal)
        .sort((a, b) => a.mes.localeCompare(b.mes))
        .map(item => {
            const [ano, mes] = item.mes.split('-');

            const nomeMes = new Date(
                Number(ano),
                Number(mes) - 1,
                1,
                12
            ).toLocaleDateString('pt-BR', {
                month: 'long',
                year: 'numeric'
            });

            return {
                ...item,
                nomeMes: nomeMes.charAt(0).toUpperCase() + nomeMes.slice(1)
            };
        });


    res.render('relatorios', {
        movimentacoes,
        produtos,
        totalEntradas,
        totalSaidas,
        produtosRanking,
        movimentacoesPorMes,
        dataInicio: dataInicio || '',
        dataFim: dataFim || ''
    });
});




// Página de nova movimentação
app.get('/movimentacoes/nova', async (req, res) => {

    const { data: produtos, error } = await supabase
        .from('produtos')
        .select('*')
        .order('nome', { ascending: true });

    if (error) {
        console.error(error);
        return res.status(500).send('Erro ao buscar produtos');
    }

    res.render('nova-movimentacao', {
        produtos,
        erro: req.query.erro || ''
    });
});


app.get('/relatorios/exportar', async (req, res) => {
    const { dataInicio, dataFim } = req.query;

    // Validar as datas recebidas
    const dataValida = data =>
        !data || /^\d{4}-\d{2}-\d{2}$/.test(data);

    if (
        !dataValida(dataInicio) ||
        !dataValida(dataFim) ||
        (dataInicio && dataFim && dataInicio > dataFim)
    ) {
        return res.status(400).send('Período de datas inválido.');
    }

    let consulta = supabase
        .from('movimentacoes')
        .select(`
            id,
            tipo,
            quantidade,
            data,
            produtos (
                id,
                nome
            )
        `)
        .order('data', { ascending: false });

    if (dataInicio) {
        consulta = consulta.gte('data', `${dataInicio}T00:00:00`);
    }

    if (dataFim) {
        consulta = consulta.lte('data', `${dataFim}T23:59:59.999`);
    }

    const { data: movimentacoes, error } = await consulta;

    if (error) {
        console.error('Erro ao exportar relatório:', error);
        return res.status(500).send('Erro ao exportar relatório.');
    }

    const escaparCSV = valor =>
        `"${String(valor ?? '').replace(/"/g, '""')}"`;

    const linhas = [
        ['Código', 'Produto', 'Tipo', 'Quantidade', 'Data'],
        ...movimentacoes.map(m => [
            `MAT${String(m.produtos?.id ?? '').padStart(3, '0')}`,
            m.produtos?.nome ?? 'Produto não encontrado',
            m.tipo,
            m.quantidade,
            m.data
                ? new Date(m.data).toLocaleString('pt-BR', {
                    timeZone: 'America/Sao_Paulo'
                })
                : ''
        ])
    ];

    const csv = '\uFEFF' + linhas
        .map(linha => linha.map(escaparCSV).join(';'))
        .join('\r\n');

    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader(
        'Content-Disposition',
        'attachment; filename="relatorio-estoque.csv"'
    );

    return res.send(csv);
});



 // Registrar movimentação
app.post('/movimentacoes', async (req, res) => {

    const { produto_id, tipo, quantidade } = req.body;

    const produtoIdNumero = Number(produto_id);
    const quantidadeNumero = Number(quantidade);

    // Verifica se a quantidade é válida
    if (!Number.isInteger(quantidadeNumero) || quantidadeNumero <= 0) {
        return res.redirect('/movimentacoes/nova?erro=quantidade');
    }

    // Verifica o tipo da movimentação
    if (tipo !== 'Entrada' && tipo !== 'Saída') {
        return res.redirect('/movimentacoes/nova?erro=tipo');
    }

    // Verifica se o produto foi selecionado
    if (!Number.isInteger(produtoIdNumero) || produtoIdNumero <= 0) {
        return res.redirect('/movimentacoes/nova?erro=produto');
    }

    // Busca o produto atual
    const { data: produto, error: erroProduto } = await supabase
        .from('produtos')
        .select('*')
        .eq('id', produtoIdNumero)
        .maybeSingle();

    if (erroProduto) {
        console.error(erroProduto);
        return res.redirect('/movimentacoes/nova?erro=servidor');
    }

    if (!produto) {
        return res.redirect('/movimentacoes/nova?erro=produto');
    }

    // Impede saída maior que o estoque disponível
    if (tipo === 'Saída' && quantidadeNumero > produto.quantidade) {
        return res.redirect('/movimentacoes/nova?erro=estoque');
    }

    // Calcula o novo estoque
    let novaQuantidade;

    if (tipo === 'Entrada') {
        novaQuantidade = produto.quantidade + quantidadeNumero;
    } else {
        novaQuantidade = produto.quantidade - quantidadeNumero;
    }

    // Registra a movimentação
    const { error: erroMovimentacao } = await supabase
        .from('movimentacoes')
        .insert([{
            produto_id: produtoIdNumero,
            tipo: tipo,
            quantidade: quantidadeNumero
        }]);

    if (erroMovimentacao) {
        console.error(erroMovimentacao);
        return res.redirect('/movimentacoes/nova?erro=movimentacao');
    }

    // Atualiza o estoque
    const { error: erroAtualizacao } = await supabase
        .from('produtos')
        .update({ quantidade: novaQuantidade })
        .eq('id', produtoIdNumero);

    if (erroAtualizacao) {
        console.error(erroAtualizacao);
        return res.redirect('/movimentacoes/nova?erro=atualizacao');
    }

    // Redireciona com uma mensagem de sucesso
    if (tipo === 'Entrada') {
        return res.redirect('/produtos?mensagem=entradaRegistrada');
    }

    return res.redirect('/produtos?mensagem=saidaRegistrada');
});



// eeeeeeeeeeeeeeeeeeeeeeeeeeeeeee
app.listen(PORT, () => {
    console.log(`Servidor rodando em http://localhost:${PORT}`);
});