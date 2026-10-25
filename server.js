const express = require('express');
const supabase = require('./supabase');

const app = express();

app.use(express.urlencoded({ extended: true }));

app.use(express.static('public'));

const PORT = 3000;

// Configuração do EJS
app.set('view engine', 'ejs');

// Página inicial

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