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


/* ========================================
   PERMISSÕES DE USUÁRIOS
======================================== */

// Cada grupo vira um bloco na tela de configuração do usuário e cada
// item vira uma caixa de marcar. "coluna" é a coluna da tabela
// permissoes_usuarios (ver database/permissoes_usuarios.sql).
const GRUPOS_PERMISSOES = [
    {
        nome: 'Cadastro de produtos',
        icone: '▤',
        itens: [
            {
                chave: 'cadastrarProdutos',
                coluna: 'pode_cadastrar_produtos',
                nome: 'Cadastrar, editar e excluir produtos',
                descricao: 'Libera o menu "Cadastrar produto" e os botões de editar e excluir na lista de produtos.'
            }
        ]
    },
    {
        nome: 'Movimentação',
        icone: '⇄',
        itens: [
            {
                chave: 'movimentarEstoque',
                coluna: 'pode_movimentar_estoque',
                nome: 'Registrar entradas e saídas',
                descricao: 'Libera a tela "Ajuste de estoque".'
            }
        ]
    },
    {
        nome: 'Requisição',
        icone: '⇥',
        itens: [
            {
                chave: 'criarRequisicao',
                coluna: 'pode_criar_requisicao',
                nome: 'Criar requisições',
                descricao: 'Pode solicitar materiais do estoque.'
            },
            {
                chave: 'aprovarRequisicao',
                coluna: 'pode_aprovar_requisicao',
                nome: 'Aprovar e rejeitar requisições',
                descricao: 'Ao aprovar, a quantidade é descontada do estoque.'
            }
        ]
    },
    {
        nome: 'Solicitação de compra',
        icone: '🛒',
        itens: [
            {
                chave: 'criarSolicitacaoCompra',
                coluna: 'pode_criar_solicitacao_compra',
                nome: 'Criar solicitações de compra',
                descricao: 'Pode criar, editar e excluir as próprias solicitações pendentes.'
            },
            {
                chave: 'aprovarSolicitacaoCompra',
                coluna: 'pode_aprovar_solicitacao_compra',
                nome: 'Aprovar, rejeitar e receber compras',
                descricao: 'Também pode editar e excluir solicitações pendentes de qualquer usuário. Ao receber, os produtos entram no estoque.'
            }
        ]
    },
    {
        nome: 'Permissões de usuários',
        icone: '♙',
        itens: [
            {
                chave: 'gerenciarPermissoes',
                coluna: 'pode_gerenciar_permissoes',
                nome: 'Gerenciar permissões',
                descricao: 'Pode abrir esta tela e alterar as permissões dos outros usuários.'
            }
        ]
    }
];

const ITENS_PERMISSOES = GRUPOS_PERMISSOES.flatMap(grupo => grupo.itens);
const COLUNAS_PERMISSOES = ITENS_PERMISSOES.map(item => item.coluna);

function permissoesVazias(valor = false) {
    return Object.fromEntries(ITENS_PERMISSOES.map(item => [item.chave, valor]));
}

// Converte uma linha da tabela em { cadastrarProdutos: true, ... }
function linhaParaPermissoes(linha) {
    return Object.fromEntries(
        ITENS_PERMISSOES.map(item => [item.chave, linha?.[item.coluna] === true])
    );
}

function emailEhAdministrador(email) {
    const emailAdministrador = process.env.ADMIN_EMAIL?.trim().toLowerCase();
    return Boolean(emailAdministrador) && email?.trim().toLowerCase() === emailAdministrador;
}

const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;


// Carrega as permissões do usuário logado em req.permissoes e nas views.
// O administrador tem todas.
app.use(async (req, res, next) => {
    req.permissoes = permissoesVazias();

    try {
        if (req.session?.usuario) {
            if (emailEhAdministrador(req.session.usuario.email)) {
                req.permissoes = permissoesVazias(true);
            } else {
                const { data, error } = await supabaseAdmin
                    .from('permissoes_usuarios')
                    .select(COLUNAS_PERMISSOES.join(', '))
                    .eq('usuario_id', req.session.usuario.id)
                    .maybeSingle();

                if (error) throw error;

                req.permissoes = linhaParaPermissoes(data);
            }
        }
    } catch (erro) {
        console.error('Erro ao carregar permissões do usuário:', erro);
        return res.status(500).send(
            'Não foi possível verificar suas permissões. ' +
            'Verifique se o script database/permissoes_usuarios.sql foi executado no Supabase.'
        );
    }

    res.locals.permissoes = req.permissoes;
    return next();
});


// Libera a rota se o usuário tiver PELO MENOS UMA das permissões
function exigirPermissao(...chaves) {
    return (req, res, next) => {
        if (chaves.some(chave => req.permissoes?.[chave])) {
            return next();
        }

        return res.status(403).send(
            'Acesso negado. Você não tem permissão para acessar esta área. ' +
            'Fale com o administrador do sistema.'
        );
    };
}


// Lista de usuários (cada um abre a sua configuração)
app.get('/admin/permissoes', exigirPermissao('gerenciarPermissoes'), async (req, res) => {
    try {
        const [
            { data: resultado, error: erroUsuarios },
            { data: linhas, error: erroPermissoes }
        ] = await Promise.all([
            supabaseAdmin.auth.admin.listUsers({ page: 1, perPage: 1000 }),
            supabaseAdmin
                .from('permissoes_usuarios')
                .select(['usuario_id', ...COLUNAS_PERMISSOES].join(', '))
        ]);

        if (erroUsuarios) throw erroUsuarios;
        if (erroPermissoes) throw erroPermissoes;

        const mapaPermissoes = new Map(
            (linhas || []).map(linha => [linha.usuario_id, linhaParaPermissoes(linha)])
        );

        const usuarios = (resultado?.users || [])
            .map(usuario => {
                const ehAdministrador = emailEhAdministrador(usuario.email);
                const permissoes = ehAdministrador
                    ? permissoesVazias(true)
                    : mapaPermissoes.get(usuario.id) || permissoesVazias();

                return {
                    id: usuario.id,
                    email: usuario.email || '(sem e-mail)',
                    ehAdministrador,
                    ehVoceMesmo: usuario.id === req.session.usuario.id,
                    gruposLiberados: GRUPOS_PERMISSOES
                        .filter(grupo => grupo.itens.some(item => permissoes[item.chave]))
                        .map(grupo => grupo.nome),
                    totalMarcadas: ITENS_PERMISSOES.filter(item => permissoes[item.chave]).length
                };
            })
            .sort((a, b) => Number(b.ehAdministrador) - Number(a.ehAdministrador) ||
                a.email.localeCompare(b.email));

        return res.render('permissoes', {
            usuarios,
            totalPermissoes: ITENS_PERMISSOES.length,
            mensagem: req.query.mensagem || '',
            erro: req.query.erro || ''
        });
    } catch (erro) {
        console.error('Erro ao carregar permissões:', erro);
        return res.status(500).send(
            'Não foi possível carregar as permissões. ' +
            'Verifique se o script database/permissoes_usuarios.sql foi executado no Supabase.'
        );
    }
});


// Busca o usuário a configurar e diz se ele pode ser alterado
async function carregarUsuarioPermissao(req) {
    const usuarioId = req.params.usuarioId;

    if (!UUID_REGEX.test(usuarioId)) {
        return { erro: 'Usuário inválido.' };
    }

    const { data, error } = await supabaseAdmin.auth.admin.getUserById(usuarioId);

    if (error || !data?.user) {
        return { erro: 'Usuário não encontrado.' };
    }

    const usuario = data.user;
    const ehAdministrador = emailEhAdministrador(usuario.email);
    const ehVoceMesmo = usuario.id === req.session.usuario.id;

    let bloqueio = '';
    if (ehAdministrador) {
        bloqueio = 'O administrador tem acesso total e permanente.';
    } else if (ehVoceMesmo) {
        bloqueio = 'Você não pode alterar as suas próprias permissões.';
    }

    return { usuario, ehAdministrador, bloqueio };
}


// Configuração de um usuário: caixas de marcar por área
app.get('/admin/permissoes/:usuarioId', exigirPermissao('gerenciarPermissoes'), async (req, res) => {
    try {
        const resultado = await carregarUsuarioPermissao(req);

        if (resultado.erro) {
            return res.redirect('/admin/permissoes?erro=' + encodeURIComponent(resultado.erro));
        }

        let permissoes = permissoesVazias(true);

        if (!resultado.ehAdministrador) {
            const { data, error } = await supabaseAdmin
                .from('permissoes_usuarios')
                .select(COLUNAS_PERMISSOES.join(', '))
                .eq('usuario_id', resultado.usuario.id)
                .maybeSingle();

            if (error) throw error;
            permissoes = linhaParaPermissoes(data);
        }

        return res.render('permissoes-usuario', {
            usuario: {
                id: resultado.usuario.id,
                email: resultado.usuario.email || '(sem e-mail)',
                criadoEm: resultado.usuario.created_at,
                ultimoAcesso: resultado.usuario.last_sign_in_at
            },
            grupos: GRUPOS_PERMISSOES,
            permissoesUsuario: permissoes,
            bloqueio: resultado.bloqueio,
            mensagem: req.query.mensagem || ''
        });
    } catch (erro) {
        console.error('Erro ao abrir permissões do usuário:', erro);
        return res.status(500).send('Não foi possível carregar as permissões do usuário.');
    }
});


// Salvar as caixas marcadas
app.post('/admin/permissoes/:usuarioId', exigirPermissao('gerenciarPermissoes'), async (req, res) => {
    try {
        const resultado = await carregarUsuarioPermissao(req);

        if (resultado.erro || resultado.bloqueio) {
            return res.redirect(
                '/admin/permissoes?erro=' + encodeURIComponent(resultado.erro || resultado.bloqueio)
            );
        }

        // Só aceita chaves conhecidas; caixa desmarcada não é enviada = false
        const marcadas = new Set([].concat(req.body.permissoes || []));

        const linha = { usuario_id: resultado.usuario.id };
        ITENS_PERMISSOES.forEach(item => {
            linha[item.coluna] = marcadas.has(item.chave);
        });

        const { error } = await supabaseAdmin
            .from('permissoes_usuarios')
            .upsert(linha, { onConflict: 'usuario_id' });

        if (error) throw error;

        return res.redirect(
            `/admin/permissoes/${resultado.usuario.id}?mensagem=` +
            encodeURIComponent('Permissões salvas com sucesso!')
        );
    } catch (erro) {
        console.error('Erro ao salvar permissões:', erro);
        return res.redirect(
            '/admin/permissoes?erro=' + encodeURIComponent('Não foi possível salvar as permissões.')
        );
    }
});


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
app.get('/produtos/novo', exigirPermissao('cadastrarProdutos'), (req, res) => {
    res.render('novo-produto', {
        erro: req.query.erro || ''
    });
});

// Página de edição de produto
app.get('/produtos/:id/editar', exigirPermissao('cadastrarProdutos'), async (req, res) => {

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
app.post('/produtos/:id/editar', exigirPermissao('cadastrarProdutos'), async (req, res) => {

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
app.post('/produtos', exigirPermissao('cadastrarProdutos'), async (req, res) => {

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
app.post('/produtos/:id/excluir', exigirPermissao('cadastrarProdutos'), async (req, res) => {

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



/* ========================================
   REQUISIÇÕES
======================================== */

function redirecionarRequisicoes(res, tipo, texto) {
    return res.redirect(`/requisicoes?${tipo}=${encodeURIComponent(texto)}`);
}

// Redireciona para uma das telas de ação (nova, editar, excluir) com erro
function redirecionarAcaoRequisicao(res, acao, texto, id) {
    const parametros = new URLSearchParams({ erro: texto });
    if (id) parametros.set('id', id);
    return res.redirect(`/requisicoes/${acao}?${parametros}`);
}

function lerIdRequisicao(req) {
    const id = Number(req.params.id ?? req.query.id);
    return Number.isSafeInteger(id) && id > 0 ? id : null;
}

function formatarCodigoRequisicao(id) {
    return String(id).padStart(5, '0');
}

async function buscarRequisicao(id) {
    const { data, error } = await supabaseAdmin
        .from('requisicoes')
        .select('*, produtos ( id, nome, quantidade )')
        .eq('id', id)
        .maybeSingle();

    if (error) throw error;
    return data;
}

// Só o autor ou quem pode aprovar mexe numa requisição pendente
async function carregarRequisicaoGerenciavel(req, id, acao) {
    const requisicao = await buscarRequisicao(id);

    if (!requisicao) {
        return { erro: 'Requisição não encontrada.' };
    }

    if (requisicao.status !== 'Pendente') {
        return { erro: `Somente requisições pendentes podem ser ${acao}.` };
    }

    const ehAutor = requisicao.criado_por_id && requisicao.criado_por_id === req.session.usuario.id;

    if (!req.permissoes.aprovarRequisicao && !ehAutor) {
        return { erro: 'Você só pode alterar as suas próprias requisições.' };
    }

    return { requisicao };
}

// Requisições pendentes que o usuário pode editar ou excluir
async function listarRequisicoesGerenciaveis(req) {
    let consulta = supabaseAdmin
        .from('requisicoes')
        .select('id, quantidade, solicitante, observacao, data_solicitacao, produtos ( nome )')
        .eq('status', 'Pendente')
        .order('id', { ascending: false });

    if (!req.permissoes.aprovarRequisicao) {
        consulta = consulta.eq('criado_por_id', req.session.usuario.id);
    }

    const { data, error } = await consulta;
    if (error) throw error;

    // Formato da lista de escolha (partials/escolha-pendente)
    return (data || []).map(item => ({
        id: item.id,
        codigo: formatarCodigoRequisicao(item.id),
        titulo: `${item.produtos ? item.produtos.nome : 'Produto não encontrado'} — ${item.quantidade} un.`,
        detalhe: item.solicitante,
        data: item.data_solicitacao
    }));
}

// Lê e valida os campos do formulário de requisição
async function lerFormularioRequisicao(req) {
    const produtoId = Number(req.body.produto_id);
    const quantidade = Number(req.body.quantidade);
    const solicitante = String(req.body.solicitante || '').trim();
    const observacao = String(req.body.observacao || '').trim();

    if (
        !Number.isSafeInteger(produtoId) || produtoId <= 0 ||
        !Number.isSafeInteger(quantidade) || quantidade <= 0 || quantidade > 1000000 ||
        !solicitante || solicitante.length > 150 ||
        observacao.length > 1000
    ) {
        return { erro: 'Preencha os campos corretamente.' };
    }

    const { data: produto, error } = await supabaseAdmin
        .from('produtos')
        .select('id')
        .eq('id', produtoId)
        .maybeSingle();

    if (error) throw error;

    if (!produto) {
        return { erro: 'O produto selecionado não existe.' };
    }

    return {
        dados: {
            produto_id: produtoId,
            quantidade,
            solicitante,
            observacao: observacao || null
        }
    };
}


// Tela de requisições (lista)
app.get('/requisicoes', exigirPermissao('criarRequisicao', 'aprovarRequisicao'), async (req, res) => {
    try {
        const { data: requisicoes, error } = await supabaseAdmin
            .from('requisicoes')
            .select('*, produtos ( id, nome, quantidade )')
            .order('data_solicitacao', { ascending: false });

        if (error) throw error;

        return res.render('requisicoes', {
            requisicoes: requisicoes || [],
            mensagem: req.query.mensagem || '',
            erro: req.query.erro || ''
        });
    } catch (erro) {
        console.error('Erro ao carregar requisições:', erro);
        return res.status(500).send('Erro ao carregar as requisições.');
    }
});


// Tela: nova requisição
app.get('/requisicoes/nova', exigirPermissao('criarRequisicao'), async (req, res) => {
    try {
        return res.render('requisicoes-form', {
            modo: 'nova',
            produtos: await listarProdutosFormulario(),
            requisicao: null,
            gerenciaveis: [],
            erro: req.query.erro || ''
        });
    } catch (erro) {
        console.error('Erro ao abrir nova requisição:', erro);
        return redirecionarRequisicoes(res, 'erro', 'Não foi possível abrir o formulário de requisição.');
    }
});


// Criar uma nova requisição
app.post('/requisicoes', exigirPermissao('criarRequisicao'), async (req, res) => {
    try {
        const formulario = await lerFormularioRequisicao(req);

        if (formulario.erro) {
            return redirecionarAcaoRequisicao(res, 'nova', formulario.erro);
        }

        const { data, error } = await supabaseAdmin
            .from('requisicoes')
            .insert({
                ...formulario.dados,
                criado_por_id: req.session.usuario.id,
                criado_por_email: req.session.usuario.email
            })
            .select('id')
            .single();

        if (error) throw error;

        return redirecionarRequisicoes(
            res,
            'mensagem',
            `Requisição nº ${formatarCodigoRequisicao(data.id)} enviada com sucesso!`
        );
    } catch (erro) {
        console.error('Erro ao criar requisição:', erro);
        return redirecionarAcaoRequisicao(
            res,
            'nova',
            'Não foi possível criar a requisição. Verifique se o script database/requisicoes_autor.sql foi executado no Supabase.'
        );
    }
});


// Tela: editar requisição. Sem id, mostra a lista para escolher.
app.get('/requisicoes/editar', exigirPermissao('criarRequisicao', 'aprovarRequisicao'), async (req, res) => {
    try {
        const id = lerIdRequisicao(req);
        let requisicao = null;
        let erro = req.query.erro || '';

        if (id) {
            const resultado = await carregarRequisicaoGerenciavel(req, id, 'editadas');
            requisicao = resultado.requisicao || null;
            erro = resultado.erro || erro;
        }

        const [produtos, gerenciaveis] = await Promise.all([
            requisicao ? listarProdutosFormulario() : [],
            requisicao ? [] : listarRequisicoesGerenciaveis(req)
        ]);

        return res.render('requisicoes-form', {
            modo: 'editar',
            produtos,
            requisicao,
            gerenciaveis,
            erro
        });
    } catch (erro) {
        console.error('Erro ao abrir edição de requisição:', erro);
        return redirecionarRequisicoes(
            res,
            'erro',
            'Não foi possível abrir a edição. Verifique se o script database/requisicoes_autor.sql foi executado no Supabase.'
        );
    }
});


// Salvar edição (só pendentes)
app.post('/requisicoes/:id/editar', exigirPermissao('criarRequisicao', 'aprovarRequisicao'), async (req, res) => {
    const id = lerIdRequisicao(req);

    try {
        if (!id) {
            return redirecionarAcaoRequisicao(res, 'editar', 'Requisição inválida.');
        }

        const resultado = await carregarRequisicaoGerenciavel(req, id, 'editadas');

        if (resultado.erro) {
            return redirecionarAcaoRequisicao(res, 'editar', resultado.erro);
        }

        const formulario = await lerFormularioRequisicao(req);

        if (formulario.erro) {
            return redirecionarAcaoRequisicao(res, 'editar', formulario.erro, id);
        }

        const { data, error } = await supabaseAdmin
            .from('requisicoes')
            .update(formulario.dados)
            .eq('id', id)
            .eq('status', 'Pendente')
            .select('id')
            .maybeSingle();

        if (error) throw error;

        if (!data) {
            return redirecionarAcaoRequisicao(res, 'editar', 'Requisição não encontrada ou já decidida.');
        }

        return redirecionarRequisicoes(
            res,
            'mensagem',
            `Requisição nº ${formatarCodigoRequisicao(id)} atualizada com sucesso!`
        );
    } catch (erro) {
        console.error('Erro ao editar requisição:', erro);
        return redirecionarAcaoRequisicao(res, 'editar', 'Não foi possível salvar a requisição.', id);
    }
});


// Tela: excluir requisição. Sem id, mostra a lista para escolher.
app.get('/requisicoes/excluir', exigirPermissao('criarRequisicao', 'aprovarRequisicao'), async (req, res) => {
    try {
        const id = lerIdRequisicao(req);
        let requisicao = null;
        let erro = req.query.erro || '';

        if (id) {
            const resultado = await carregarRequisicaoGerenciavel(req, id, 'excluídas');
            requisicao = resultado.requisicao || null;
            erro = resultado.erro || erro;
        }

        return res.render('requisicoes-excluir', {
            requisicao,
            gerenciaveis: requisicao ? [] : await listarRequisicoesGerenciaveis(req),
            erro
        });
    } catch (erro) {
        console.error('Erro ao abrir exclusão de requisição:', erro);
        return redirecionarRequisicoes(
            res,
            'erro',
            'Não foi possível abrir a exclusão. Verifique se o script database/requisicoes_autor.sql foi executado no Supabase.'
        );
    }
});


// Excluir (só pendentes)
app.post('/requisicoes/:id/excluir', exigirPermissao('criarRequisicao', 'aprovarRequisicao'), async (req, res) => {
    const id = lerIdRequisicao(req);

    try {
        if (!id) {
            return redirecionarAcaoRequisicao(res, 'excluir', 'Requisição inválida.');
        }

        const resultado = await carregarRequisicaoGerenciavel(req, id, 'excluídas');

        if (resultado.erro) {
            return redirecionarAcaoRequisicao(res, 'excluir', resultado.erro);
        }

        const { data, error } = await supabaseAdmin
            .from('requisicoes')
            .delete()
            .eq('id', id)
            .eq('status', 'Pendente')
            .select('id')
            .maybeSingle();

        if (error) throw error;

        if (!data) {
            return redirecionarAcaoRequisicao(res, 'excluir', 'Requisição não encontrada ou já decidida.');
        }

        return redirecionarRequisicoes(
            res,
            'mensagem',
            `Requisição nº ${formatarCodigoRequisicao(id)} excluída.`
        );
    } catch (erro) {
        console.error('Erro ao excluir requisição:', erro);
        return redirecionarAcaoRequisicao(res, 'excluir', 'Não foi possível excluir a requisição.', id);
    }
});


/* Aprovar uma requisição e descontar o estoque */
app.post(
    '/requisicoes/:id/aprovar',
    exigirPermissao('aprovarRequisicao'),
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
    exigirPermissao('aprovarRequisicao'),
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
app.get('/movimentacoes/nova', exigirPermissao('movimentarEstoque'), async (req, res) => {

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
    exigirPermissao('movimentarEstoque'),
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



/* ========================================
   SOLICITAÇÕES DE COMPRA
======================================== */

const STATUS_COMPRA = ['Pendente', 'Comprada', 'Recebida', 'Rejeitada'];

// Converte "AAAA-MM-DD" (horário de Brasília) em um instante ISO
function inicioDoDiaBrasilia(dataTexto, diasAMais = 0) {
    const data = new Date(`${dataTexto}T00:00:00-03:00`);
    data.setUTCDate(data.getUTCDate() + diasAMais);
    return data.toISOString();
}

function redirecionarCompras(res, tipo, texto) {
    return res.redirect(`/compras?${tipo}=${encodeURIComponent(texto)}`);
}

function lerCodigoSolicitacao(req) {
    const codigo = Number(req.params.codigo ?? req.query.codigo);
    return Number.isSafeInteger(codigo) && codigo > 0 ? codigo : null;
}

function formatarCodigoCompra(codigo) {
    return String(codigo).padStart(5, '0');
}

// Redireciona para uma das páginas de ação (nova, editar, excluir) com erro
function redirecionarAcaoCompra(res, acao, texto, codigo) {
    const parametros = new URLSearchParams({ erro: texto });
    if (codigo) parametros.set('codigo', codigo);
    return res.redirect(`/compras/${acao}?${parametros}`);
}

// Só o próprio solicitante ou quem pode aprovar mexe numa solicitação
function podeGerenciarSolicitacao(req, solicitacao, podeAprovar) {
    return podeAprovar || solicitacao.solicitante_id === req.session.usuario.id;
}

async function buscarSolicitacaoCompra(codigo) {
    const { data, error } = await supabaseAdmin
        .from('solicitacoes_compra')
        .select(`
            *,
            solicitacoes_compra_itens (
                id,
                produto_id,
                quantidade,
                produtos ( id, nome )
            )
        `)
        .eq('codigo', codigo)
        .maybeSingle();

    if (error) throw error;
    return data;
}

// Solicitações pendentes que o usuário pode editar ou excluir
async function listarSolicitacoesGerenciaveis(req, podeAprovar) {
    let consulta = supabaseAdmin
        .from('solicitacoes_compra')
        .select('codigo, motivo, solicitante_email, data_solicitacao')
        .eq('status', 'Pendente')
        .order('codigo', { ascending: false });

    if (!podeAprovar) {
        consulta = consulta.eq('solicitante_id', req.session.usuario.id);
    }

    const { data, error } = await consulta;
    if (error) throw error;
    // Formato da lista de escolha (partials/escolha-pendente)
    return (data || []).map(item => ({
        id: item.codigo,
        codigo: formatarCodigoCompra(item.codigo),
        titulo: item.motivo,
        detalhe: item.solicitante_email,
        data: item.data_solicitacao
    }));
}

async function listarProdutosFormulario() {
    const { data, error } = await supabaseAdmin
        .from('produtos')
        .select('id, nome, quantidade')
        .order('nome', { ascending: true });

    if (error) throw error;
    return data || [];
}

// Lê e valida motivo + itens do formulário. Junta produtos repetidos.
async function lerFormularioSolicitacao(req) {
    const motivo = String(req.body.motivo || '').trim();
    const produtosIds = [].concat(req.body.produto_id || []);
    const quantidades = [].concat(req.body.quantidade || []);

    if (!motivo || motivo.length > 1000) {
        return { erro: 'Informe o motivo da solicitação (até 1000 caracteres).' };
    }

    if (produtosIds.length === 0 || produtosIds.length !== quantidades.length || produtosIds.length > 50) {
        return { erro: 'Adicione de 1 a 50 produtos à solicitação.' };
    }

    const itensPorProduto = new Map();

    for (let i = 0; i < produtosIds.length; i++) {
        const produtoId = Number(produtosIds[i]);
        const quantidade = Number(quantidades[i]);

        if (
            !Number.isSafeInteger(produtoId) || produtoId <= 0 ||
            !Number.isSafeInteger(quantidade) || quantidade <= 0 || quantidade > 1000000
        ) {
            return { erro: 'Selecione os produtos e informe quantidades válidas.' };
        }

        itensPorProduto.set(produtoId, (itensPorProduto.get(produtoId) || 0) + quantidade);
    }

    const idsProdutos = [...itensPorProduto.keys()];

    const { data: produtosExistentes, error } = await supabaseAdmin
        .from('produtos')
        .select('id')
        .in('id', idsProdutos);

    if (error) throw error;

    if ((produtosExistentes || []).length !== idsProdutos.length) {
        return { erro: 'Um dos produtos selecionados não existe mais.' };
    }

    return {
        motivo,
        itens: idsProdutos.map(produtoId => ({
            produto_id: produtoId,
            quantidade: itensPorProduto.get(produtoId)
        }))
    };
}


// Tela de solicitações de compra (histórico com filtros)
app.get('/compras', exigirPermissao('criarSolicitacaoCompra', 'aprovarSolicitacaoCompra'), async (req, res) => {
    try {
        const filtros = {
            codigo: String(req.query.codigo || '').replace(/\D/g, ''),
            status: STATUS_COMPRA.includes(req.query.status) ? req.query.status : '',
            usuario: String(req.query.usuario || '').trim().toLowerCase(),
            dataInicial: /^\d{4}-\d{2}-\d{2}$/.test(req.query.dataInicial || '')
                ? req.query.dataInicial : '',
            dataFinal: /^\d{4}-\d{2}-\d{2}$/.test(req.query.dataFinal || '')
                ? req.query.dataFinal : ''
        };

        let consulta = supabaseAdmin
            .from('solicitacoes_compra')
            .select(`
                *,
                solicitacoes_compra_itens (
                    id,
                    quantidade,
                    produtos ( id, nome )
                )
            `)
            .order('codigo', { ascending: false });

        if (filtros.codigo) {
            consulta = consulta.eq('codigo', Number(filtros.codigo));
        }

        if (filtros.status) {
            consulta = consulta.eq('status', filtros.status);
        }

        // Usuário: quem solicitou OU quem aprovou/rejeitou
        if (filtros.usuario && /^[^\s,()"]+@[^\s,()"]+$/.test(filtros.usuario)) {
            consulta = consulta.or(
                `solicitante_email.eq."${filtros.usuario}",aprovador_email.eq."${filtros.usuario}"`
            );
        }

        if (filtros.dataInicial) {
            consulta = consulta.gte('data_solicitacao', inicioDoDiaBrasilia(filtros.dataInicial));
        }

        if (filtros.dataFinal) {
            consulta = consulta.lt('data_solicitacao', inicioDoDiaBrasilia(filtros.dataFinal, 1));
        }

        const [
            { data: solicitacoes, error: erroSolicitacoes },
            { data: listaUsuarios, error: erroUsuarios }
        ] = await Promise.all([
            consulta,
            supabaseAdmin.auth.admin.listUsers({ page: 1, perPage: 1000 })
        ]);

        const podeAprovar = req.permissoes.aprovarSolicitacaoCompra;

        if (erroSolicitacoes) throw erroSolicitacoes;
        if (erroUsuarios) throw erroUsuarios;

        const usuarios = (listaUsuarios?.users || [])
            .map(usuario => usuario.email?.trim().toLowerCase())
            .filter(Boolean)
            .sort();

        return res.render('compras', {
            solicitacoes: solicitacoes || [],
            usuarios,
            statusDisponiveis: STATUS_COMPRA,
            filtros,
            podeAprovar,
            mensagem: req.query.mensagem || '',
            erro: req.query.erro || ''
        });
    } catch (erro) {
        console.error('Erro ao carregar solicitações de compra:', erro);
        return res.status(500).send(
            'Erro ao carregar as solicitações de compra. ' +
            'Verifique se o script database/solicitacoes_compra.sql foi executado no Supabase.'
        );
    }
});


// Página: nova solicitação
app.get('/compras/nova', exigirPermissao('criarSolicitacaoCompra'), async (req, res) => {
    try {
        return res.render('compras-form', {
            modo: 'nova',
            produtos: await listarProdutosFormulario(),
            solicitacao: null,
            gerenciaveis: [],
            erro: req.query.erro || ''
        });
    } catch (erro) {
        console.error('Erro ao abrir nova solicitação de compra:', erro);
        return redirecionarCompras(res, 'erro', 'Não foi possível abrir o formulário de solicitação.');
    }
});


// Criar uma nova solicitação de compra
app.post('/compras', exigirPermissao('criarSolicitacaoCompra'), async (req, res) => {
    try {
        const formulario = await lerFormularioSolicitacao(req);

        if (formulario.erro) {
            return redirecionarAcaoCompra(res, 'nova', formulario.erro);
        }

        const { data: codigo, error } = await supabaseAdmin.rpc('criar_solicitacao_compra', {
            p_solicitante_id: req.session.usuario.id,
            p_solicitante_email: req.session.usuario.email,
            p_motivo: formulario.motivo,
            p_itens: formulario.itens
        });

        if (error) throw error;

        return redirecionarCompras(
            res,
            'mensagem',
            `Solicitação nº ${formatarCodigoCompra(codigo)} criada com sucesso!`
        );
    } catch (erro) {
        console.error('Erro ao criar solicitação de compra:', erro);
        return redirecionarAcaoCompra(res, 'nova', 'Não foi possível criar a solicitação de compra.');
    }
});


// Valida se a solicitação pode ser editada/excluída pelo usuário.
// Retorna { solicitacao } ou { erro }.
async function carregarSolicitacaoGerenciavel(req, codigo, podeAprovar, acao) {
    const solicitacao = await buscarSolicitacaoCompra(codigo);

    if (!solicitacao) {
        return { erro: 'Solicitação não encontrada.' };
    }

    if (solicitacao.status !== 'Pendente') {
        return { erro: `Somente solicitações pendentes podem ser ${acao}.` };
    }

    if (!podeGerenciarSolicitacao(req, solicitacao, podeAprovar)) {
        return { erro: 'Você só pode alterar as suas próprias solicitações.' };
    }

    return { solicitacao };
}


// Página: editar solicitação. Sem código, mostra a lista para escolher.
app.get('/compras/editar', exigirPermissao('criarSolicitacaoCompra', 'aprovarSolicitacaoCompra'), async (req, res) => {
    try {
        const podeAprovar = req.permissoes.aprovarSolicitacaoCompra;
        const codigo = lerCodigoSolicitacao(req);
        let solicitacao = null;
        let erro = req.query.erro || '';

        if (codigo) {
            const resultado = await carregarSolicitacaoGerenciavel(req, codigo, podeAprovar, 'editadas');
            solicitacao = resultado.solicitacao || null;
            erro = resultado.erro || erro;
        }

        const [produtos, gerenciaveis] = await Promise.all([
            solicitacao ? listarProdutosFormulario() : [],
            solicitacao ? [] : listarSolicitacoesGerenciaveis(req, podeAprovar)
        ]);

        return res.render('compras-form', {
            modo: 'editar',
            produtos,
            solicitacao,
            gerenciaveis,
            erro
        });
    } catch (erro) {
        console.error('Erro ao abrir edição de solicitação de compra:', erro);
        return redirecionarCompras(res, 'erro', 'Não foi possível abrir a edição da solicitação.');
    }
});


// Salvar edição (só pendentes)
app.post('/compras/:codigo/editar', exigirPermissao('criarSolicitacaoCompra', 'aprovarSolicitacaoCompra'), async (req, res) => {
    const codigo = lerCodigoSolicitacao(req);

    try {
        if (!codigo) {
            return redirecionarAcaoCompra(res, 'editar', 'Código de solicitação inválido.');
        }

        const podeAprovar = req.permissoes.aprovarSolicitacaoCompra;
        const resultado = await carregarSolicitacaoGerenciavel(req, codigo, podeAprovar, 'editadas');

        if (resultado.erro) {
            return redirecionarAcaoCompra(res, 'editar', resultado.erro);
        }

        const formulario = await lerFormularioSolicitacao(req);

        if (formulario.erro) {
            return redirecionarAcaoCompra(res, 'editar', formulario.erro, codigo);
        }

        const { data: editou, error } = await supabaseAdmin.rpc('editar_solicitacao_compra', {
            p_codigo: codigo,
            p_motivo: formulario.motivo,
            p_itens: formulario.itens
        });

        if (error) throw error;

        if (!editou) {
            return redirecionarAcaoCompra(res, 'editar', 'Solicitação não encontrada ou já decidida.');
        }

        return redirecionarCompras(
            res,
            'mensagem',
            `Solicitação nº ${formatarCodigoCompra(codigo)} atualizada com sucesso!`
        );
    } catch (erro) {
        console.error('Erro ao editar solicitação de compra:', erro);
        return redirecionarAcaoCompra(
            res,
            'editar',
            'Não foi possível salvar a solicitação. Verifique se o script database/solicitacoes_compra_edicao.sql foi executado no Supabase.',
            codigo
        );
    }
});


// Página: excluir solicitação. Sem código, mostra a lista para escolher.
app.get('/compras/excluir', exigirPermissao('criarSolicitacaoCompra', 'aprovarSolicitacaoCompra'), async (req, res) => {
    try {
        const podeAprovar = req.permissoes.aprovarSolicitacaoCompra;
        const codigo = lerCodigoSolicitacao(req);
        let solicitacao = null;
        let erro = req.query.erro || '';

        if (codigo) {
            const resultado = await carregarSolicitacaoGerenciavel(req, codigo, podeAprovar, 'excluídas');
            solicitacao = resultado.solicitacao || null;
            erro = resultado.erro || erro;
        }

        return res.render('compras-excluir', {
            solicitacao,
            gerenciaveis: solicitacao ? [] : await listarSolicitacoesGerenciaveis(req, podeAprovar),
            erro
        });
    } catch (erro) {
        console.error('Erro ao abrir exclusão de solicitação de compra:', erro);
        return redirecionarCompras(res, 'erro', 'Não foi possível abrir a exclusão da solicitação.');
    }
});


// Excluir (só pendentes; os itens saem junto pelo "on delete cascade")
app.post('/compras/:codigo/excluir', exigirPermissao('criarSolicitacaoCompra', 'aprovarSolicitacaoCompra'), async (req, res) => {
    const codigo = lerCodigoSolicitacao(req);

    try {
        if (!codigo) {
            return redirecionarAcaoCompra(res, 'excluir', 'Código de solicitação inválido.');
        }

        const podeAprovar = req.permissoes.aprovarSolicitacaoCompra;
        const resultado = await carregarSolicitacaoGerenciavel(req, codigo, podeAprovar, 'excluídas');

        if (resultado.erro) {
            return redirecionarAcaoCompra(res, 'excluir', resultado.erro);
        }

        const { data, error } = await supabaseAdmin
            .from('solicitacoes_compra')
            .delete()
            .eq('codigo', codigo)
            .eq('status', 'Pendente')
            .select('codigo')
            .maybeSingle();

        if (error) throw error;

        if (!data) {
            return redirecionarAcaoCompra(res, 'excluir', 'Solicitação não encontrada ou já decidida.');
        }

        return redirecionarCompras(
            res,
            'mensagem',
            `Solicitação nº ${formatarCodigoCompra(codigo)} excluída.`
        );
    } catch (erro) {
        console.error('Erro ao excluir solicitação de compra:', erro);
        return redirecionarAcaoCompra(res, 'excluir', 'Não foi possível excluir a solicitação.', codigo);
    }
});


// Aprovar: Pendente → Comprada
app.post('/compras/:codigo/aprovar', exigirPermissao('aprovarSolicitacaoCompra'), async (req, res) => {
    try {
        const codigo = lerCodigoSolicitacao(req);

        if (!codigo) {
            return redirecionarCompras(res, 'erro', 'Código de solicitação inválido.');
        }

        const { data, error } = await supabaseAdmin
            .from('solicitacoes_compra')
            .update({
                status: 'Comprada',
                aprovador_email: req.session.usuario.email,
                data_decisao: new Date().toISOString()
            })
            .eq('codigo', codigo)
            .eq('status', 'Pendente')
            .select('codigo')
            .maybeSingle();

        if (error) throw error;

        if (!data) {
            return redirecionarCompras(res, 'erro', 'Solicitação não encontrada ou já decidida.');
        }

        return redirecionarCompras(res, 'mensagem', 'Solicitação aprovada. Status alterado para Comprada.');
    } catch (erro) {
        console.error('Erro ao aprovar solicitação de compra:', erro);
        return redirecionarCompras(res, 'erro', 'Não foi possível aprovar a solicitação.');
    }
});


// Rejeitar: Pendente → Rejeitada (exige motivo)
app.post('/compras/:codigo/rejeitar', exigirPermissao('aprovarSolicitacaoCompra'), async (req, res) => {
    try {
        const codigo = lerCodigoSolicitacao(req);
        const motivo = String(req.body.motivo_rejeicao || '').trim();

        if (!codigo || !motivo || motivo.length > 1000) {
            return redirecionarCompras(res, 'erro', 'Informe o motivo da rejeição.');
        }

        const { data, error } = await supabaseAdmin
            .from('solicitacoes_compra')
            .update({
                status: 'Rejeitada',
                aprovador_email: req.session.usuario.email,
                data_decisao: new Date().toISOString(),
                motivo_rejeicao: motivo
            })
            .eq('codigo', codigo)
            .eq('status', 'Pendente')
            .select('codigo')
            .maybeSingle();

        if (error) throw error;

        if (!data) {
            return redirecionarCompras(res, 'erro', 'Solicitação não encontrada ou já decidida.');
        }

        return redirecionarCompras(res, 'mensagem', 'Solicitação rejeitada.');
    } catch (erro) {
        console.error('Erro ao rejeitar solicitação de compra:', erro);
        return redirecionarCompras(res, 'erro', 'Não foi possível rejeitar a solicitação.');
    }
});


// Receber: Comprada → Recebida (dá entrada no estoque)
app.post('/compras/:codigo/receber', exigirPermissao('aprovarSolicitacaoCompra'), async (req, res) => {
    try {
        const codigo = lerCodigoSolicitacao(req);

        if (!codigo) {
            return redirecionarCompras(res, 'erro', 'Código de solicitação inválido.');
        }

        const { error } = await supabaseAdmin.rpc('receber_solicitacao_compra', {
            p_codigo: codigo,
            p_responsavel: req.session.usuario.email
        });

        if (error) {
            console.error('Erro ao receber solicitação de compra:', error);
            return redirecionarCompras(res, 'erro', 'Não foi possível registrar o recebimento. A solicitação precisa estar com status Comprada.');
        }

        return redirecionarCompras(res, 'mensagem', 'Recebimento registrado e estoque atualizado!');
    } catch (erro) {
        console.error('Erro ao receber solicitação de compra:', erro);
        return redirecionarCompras(res, 'erro', 'Não foi possível registrar o recebimento.');
    }
});


app.listen(PORT, () => {
    console.log(`Servidor rodando em http://localhost:${PORT}`);
});