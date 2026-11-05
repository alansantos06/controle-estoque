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


app.use((req, res, next) => {
    const emailAdministrador = process.env.ADMIN_EMAIL
        ?.trim()
        .toLowerCase();

    res.locals.ehAdministrador =
        req.session.usuario?.email?.trim().toLowerCase() ===
        emailAdministrador;

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




async function exigirPermissaoMovimentacao(req, res, next) {
    const emailUsuario = req.session?.usuario?.email
        ?.trim()
        .toLowerCase();

    const emailAdministrador = process.env.ADMIN_EMAIL
        ?.trim()
        .toLowerCase();

    // O administrador sempre tem permissão
    if (
        emailUsuario &&
        emailAdministrador &&
        emailUsuario === emailAdministrador
    ) {
        return next();
    }

    // Sem usuário autenticado, não permite continuar
    if (!req.session?.usuario?.id) {
        return res.redirect('/login');
    }

    try {
        const { data, error } = await supabaseAdmin
            .from('permissoes_usuarios')
            .select('pode_movimentar_estoque')
            .eq('usuario_id', req.session.usuario.id)
            .maybeSingle();

        if (error) {
            console.error('Erro ao verificar permissão:', error);
            return res.status(500).send(
                'Não foi possível verificar suas permissões.'
            );
        }

        if (!data?.pode_movimentar_estoque) {
            return res.status(403).send(
                'Você não tem permissão para movimentar o estoque.'
            );
        }

        return next();
    } catch (erro) {
        console.error('Erro ao verificar permissão:', erro);
        return res.status(500).send(
            'Não foi possível verificar suas permissões.'
        );
    }
}


// Listar usuários e suas permissões
app.get(
    '/admin/permissoes',
    exigirAdministrador,
    async (req, res) => {
        try {
            const { data: resultado, error: erroUsuarios } =
                await supabaseAdmin.auth.admin.listUsers({
                    page: 1,
                    perPage: 1000
                });

            if (erroUsuarios) {
                console.error('Erro ao listar usuários:', erroUsuarios);
                return res.status(500).send(
                    'Não foi possível listar os usuários.'
                );
            }

            const { data: permissoes, error: erroPermissoes } =
                await supabaseAdmin
                    .from('permissoes_usuarios')
                    .select('usuario_id, pode_movimentar_estoque');

            if (erroPermissoes) {
                console.error('Erro ao consultar permissões:', erroPermissoes);
                return res.status(500).send(
                    'Não foi possível consultar as permissões.'
                );
            }

            const mapaPermissoes = new Map(
                (permissoes || []).map(permissao => [
                    permissao.usuario_id,
                    permissao.pode_movimentar_estoque
                ])
            );

            const emailAdministrador = process.env.ADMIN_EMAIL
                ?.trim()
                .toLowerCase();

            const usuarios = resultado.users.map(usuario => {
                const ehAdministrador =
                    usuario.email?.trim().toLowerCase() === emailAdministrador;

                return {
                    id: usuario.id,
                    email: usuario.email || '(sem e-mail)',
                    ehAdministrador,
                    podeMovimentar: ehAdministrador ||
                        mapaPermissoes.get(usuario.id) === true
                };
            });

            return res.render('permissoes', {
                usuarios,
                mensagem: req.query.mensagem || ''
            });
        } catch (erro) {
            console.error('Erro ao carregar permissões:', erro);
            return res.status(500).send(
                'Ocorreu um erro ao carregar o gerenciamento de permissões.'
            );
        }
    }
);


// Conceder ou retirar permissão de movimentação
app.post(
    '/admin/permissoes/:usuarioId',
    exigirAdministrador,
    async (req, res) => {
        try {
            const usuarioId = req.params.usuarioId;
            const acao = req.body.acao;

            if (
                !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(usuarioId) ||
                !['conceder', 'retirar'].includes(acao)
            ) {
                return res.status(400).send('Dados inválidos.');
            }

            const emailAdministrador = process.env.ADMIN_EMAIL
                ?.trim()
                .toLowerCase();

            const { data: usuario, error: erroUsuario } =
                await supabaseAdmin.auth.admin.getUserById(usuarioId);

            if (erroUsuario || !usuario.user) {
                return res.status(404).send('Usuário não encontrado.');
            }

            if (
                usuario.user.email?.trim().toLowerCase() === emailAdministrador
            ) {
                return res.status(400).send(
                    'O administrador já possui acesso permanente.'
                );
            }

            if (acao === 'conceder') {
                const { error } = await supabaseAdmin
                    .from('permissoes_usuarios')
                    .upsert(
                        {
                            usuario_id: usuarioId,
                            pode_movimentar_estoque: true
                        },
                        { onConflict: 'usuario_id' }
                    );

                if (error) throw error;
            } else {
                const { error } = await supabaseAdmin
                    .from('permissoes_usuarios')
                    .delete()
                    .eq('usuario_id', usuarioId);

                if (error) throw error;
            }

            return res.redirect(
                '/admin/permissoes?mensagem=' +
                (acao === 'conceder' ? 'concedida' : 'retirada')
            );
        } catch (erro) {
            console.error('Erro ao alterar permissão:', erro);
            return res.status(500).send(
                'Não foi possível alterar a permissão.'
            );
        }
    }
);




app.get('/admin/permissoes', exigirAdministrador, async (req, res) => {
    try {
        const { data: resultado, error: erroUsuarios } =
            await supabaseAdmin.auth.admin.listUsers({
                page: 1,
                perPage: 1000
            });

        if (erroUsuarios) {
            console.error('Erro ao listar usuários:', erroUsuarios);
            return res.status(500).send('Erro ao listar usuários.');
        }

        const { data: permissoes, error: erroPermissoes } =
            await supabaseAdmin
                .from('permissoes_usuarios')
                .select('usuario_id, pode_movimentar_estoque');

        if (erroPermissoes) {
            console.error('Erro ao buscar permissões:', erroPermissoes);
            return res.status(500).send('Erro ao buscar permissões.');
        }

        const mapaPermissoes = new Map(
            (permissoes || []).map(p => [
                p.usuario_id,
                p.pode_movimentar_estoque
            ])
        );

        const emailAdministrador = process.env.ADMIN_EMAIL
            ?.trim()
            .toLowerCase();

        const usuarios = resultado.users.map(usuario => {
            const ehAdministrador =
                usuario.email?.trim().toLowerCase() === emailAdministrador;

            return {
                id: usuario.id,
                email: usuario.email || '(sem e-mail)',
                ehAdministrador,
                podeMovimentar:
                    ehAdministrador ||
                    mapaPermissoes.get(usuario.id) === true
            };
        });

        return res.render('permissoes', {
            usuarios,
            mensagem: req.query.mensagem || ''
        });
    } catch (erro) {
        console.error('Erro ao abrir permissões:', erro);
        return res.status(500).send('Não foi possível carregar as permissões.');
    }
});




// Proteger as páginas e operações do sistema
app.use((req, res, next) => {
    const rotasPublicas = [
        '/login',
        '/recuperar-senha',
        '/redefinir-senha'
    ];

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

    const mensagem = req.query.mensagem === 'senhaRedefinida'
        ? 'Senha redefinida com sucesso. Entre com a nova senha.'
        : '';

    res.render('login', { erro: '', mensagem });
});

// Página "Esqueci minha senha"
app.get('/recuperar-senha', (req, res) => {
    res.render('recuperar-senha', { erro: '', mensagem: '' });
});

// Envia o e-mail de recuperação pelo Supabase
app.post('/recuperar-senha', async (req, res) => {
    const email = String(req.body.email || '').trim();

    if (!email) {
        return res.status(400).render('recuperar-senha', {
            erro: 'Informe o e-mail.',
            mensagem: ''
        });
    }

    const urlBase = process.env.APP_URL || `http://localhost:${PORT}`;

    const { error } = await supabaseAuth.auth.resetPasswordForEmail(email, {
        redirectTo: `${urlBase}/redefinir-senha`
    });

    if (error) {
        console.error('Erro ao enviar e-mail de recuperação:', error.message);

        if (error.status === 429) {
            return res.status(429).render('recuperar-senha', {
                erro: 'Muitas tentativas. Aguarde alguns minutos e tente novamente.',
                mensagem: ''
            });
        }
    }

    // Mensagem genérica para não revelar quais e-mails estão cadastrados
    return res.render('recuperar-senha', {
        erro: '',
        mensagem: 'Se o e-mail estiver cadastrado, você receberá um link para redefinir a senha.'
    });
});

// Página para definir a nova senha (aberta pelo link do e-mail)
app.get('/redefinir-senha', (req, res) => {
    res.render('redefinir-senha', { erro: '', token: '' });
});

// Salva a nova senha
app.post('/redefinir-senha', async (req, res) => {
    const token = String(req.body.token || '');
    const senha = String(req.body.senha || '');
    const confirmacao = String(req.body.confirmacao || '');

    const renderErro = (erro, status = 400) =>
        res.status(status).render('redefinir-senha', { erro, token });

    if (!token) {
        return renderErro('Link de recuperação inválido. Solicite um novo.');
    }

    if (senha.length < 6) {
        return renderErro('A senha precisa ter pelo menos 6 caracteres.');
    }

    if (senha !== confirmacao) {
        return renderErro('As senhas não conferem.');
    }

    try {
        // Valida o token do link e descobre de qual usuário ele é
        const { data, error } = await supabaseAdmin.auth.getUser(token);

        if (error || !data?.user) {
            return renderErro(
                'O link de recuperação é inválido ou expirou. Solicite um novo.',
                401
            );
        }

        const { error: erroAtualizacao } =
            await supabaseAdmin.auth.admin.updateUserById(data.user.id, {
                password: senha
            });

        if (erroAtualizacao) {
            console.error('Erro ao redefinir senha:', erroAtualizacao.message);
            return renderErro('Não foi possível salvar a nova senha.', 500);
        }

        return res.redirect('/login?mensagem=senhaRedefinida');
    } catch (erro) {
        console.error('Erro ao redefinir senha:', erro);
        return renderErro('Ocorreu um erro ao redefinir a senha.', 500);
    }
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
                encodeURIComponent(
                    'Não foi possível aprovar a requisição. Verifique o estoque e tente novamente.'
                )
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
    const { tipo, dataInicial, dataFinal } = req.query;

    let consulta = supabaseAdmin
        .from('movimentacoes')
        .select('id, tipo, quantidade, data, produtos(id, nome)')
        .order('data', { ascending: false });

    if (tipo === 'Entrada' || tipo === 'Saída') {
        consulta = consulta.eq('tipo', tipo);
    }

    if (dataInicial) {
        consulta = consulta.gte('data', `${dataInicial}T00:00:00`);
    }

    if (dataFinal) {
        const diaSeguinte = new Date(`${dataFinal}T12:00:00`);
        diaSeguinte.setDate(diaSeguinte.getDate() + 1);

        const ano = diaSeguinte.getFullYear();
        const mes = String(diaSeguinte.getMonth() + 1).padStart(2, '0');
        const dia = String(diaSeguinte.getDate()).padStart(2, '0');

        consulta = consulta.lt(
            'data',
            `${ano}-${mes}-${dia}T00:00:00`
        );
    }

    const { data: movimentacoes, error } = await consulta;

    if (error) {
        console.error('Erro ao buscar movimentações:', error);
        return res.status(500).send('Erro ao carregar o histórico.');
    }

    res.render('historico', {
        movimentacoes: movimentacoes || [],
        tipoSelecionado: tipo || 'Todos',
        dataInicial: dataInicial || '',
        dataFinal: dataFinal || ''
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
app.post(
    '/movimentacoes',
    exigirPermissaoMovimentacao,
    async (req, res) => {

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