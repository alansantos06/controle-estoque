// Seleção de uma linha pendente na tabela (requisições / solicitações de compra)
// e ações sobre ela: 👍 aprovar, 👎 rejeitar, Editar e Excluir.
(function () {
    var linhas = document.querySelectorAll('.linha-selecionavel');
    var dialogo = document.getElementById('dialogoDecisao');
    var aviso = document.getElementById('avisoSelecao');
    var selecionada = null;
    var timerAviso = null;

    var ICONES = {
        aprovar: '<svg viewBox="0 0 24 24" width="26" height="26" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 9V5a3 3 0 0 0-3-3l-4 9v11h11.28a2 2 0 0 0 2-1.7l1.38-9a2 2 0 0 0-2-2.3z"/><path d="M7 22H4a2 2 0 0 1-2-2v-7a2 2 0 0 1 2-2h3"/></svg>',
        rejeitar: '<svg viewBox="0 0 24 24" width="26" height="26" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M10 15v4a3 3 0 0 0 3 3l4-9V2H5.72a2 2 0 0 0-2 1.7l-1.38 9a2 2 0 0 0 2 2.3z"/><path d="M17 2h2.67A2.31 2.31 0 0 1 22 4v7a2.31 2.31 0 0 1-2.33 2H17"/></svg>'
    };

    function selecionar(linha) {
        var mesma = selecionada === linha;

        linhas.forEach(function (outra) {
            outra.classList.remove('linha-selecionada');
            outra.setAttribute('aria-selected', 'false');
        });

        // Clicar de novo na mesma linha desfaz a seleção
        selecionada = mesma ? null : linha;

        if (selecionada) {
            selecionada.classList.add('linha-selecionada');
            selecionada.setAttribute('aria-selected', 'true');
            esconderAviso();
        }

        document.body.classList.toggle('tem-selecao', Boolean(selecionada));
    }

    function mostrarAviso() {
        if (!aviso) return;
        aviso.hidden = false;
        clearTimeout(timerAviso);
        timerAviso = setTimeout(esconderAviso, 3000);
    }

    function esconderAviso() {
        if (aviso) aviso.hidden = true;
    }

    linhas.forEach(function (linha) {
        linha.addEventListener('click', function (evento) {
            // Cliques em botões/links/campos dentro da linha não selecionam
            if (evento.target.closest('a, button, input, textarea, select, form')) return;
            selecionar(linha);
        });

        linha.addEventListener('keydown', function (evento) {
            if (evento.key === 'Enter' || evento.key === ' ') {
                evento.preventDefault();
                selecionar(linha);
            }
        });
    });

    // Editar / Excluir: com uma linha selecionada, vão direto para ela
    document.querySelectorAll('[data-selecao-href]').forEach(function (link) {
        link.addEventListener('click', function (evento) {
            if (!selecionada) return;
            evento.preventDefault();
            window.location.href = link.getAttribute('data-selecao-href') + selecionada.getAttribute('data-id');
        });
    });

    // 👍 / 👎
    document.querySelectorAll('[data-decisao]').forEach(function (botao) {
        botao.addEventListener('click', function (evento) {
            if (!dialogo || typeof dialogo.showModal !== 'function') return; // sem suporte: segue o link
            evento.preventDefault();

            if (!selecionada) {
                mostrarAviso();
                return;
            }

            abrirDialogo(botao.getAttribute('data-decisao'));
        });
    });

    function abrirDialogo(acao) {
        var aprovando = acao === 'aprovar';
        var base = dialogo.getAttribute('data-base');
        var singular = base === '/requisicoes' ? 'requisição' : 'solicitação';
        var codigo = selecionada.getAttribute('data-codigo');
        var alerta = selecionada.getAttribute('data-alerta') || '';

        var form = document.getElementById('dialogoForm');
        var icone = document.getElementById('dialogoIcone');
        var motivo = document.getElementById('dialogoMotivo');
        var confirmar = document.getElementById('dialogoConfirmar');
        var caixaAlerta = document.getElementById('dialogoAlerta');

        form.action = base + '/' + selecionada.getAttribute('data-id') + '/' + acao;

        document.getElementById('dialogoTitulo').textContent =
            (aprovando ? 'Aprovar ' : 'Rejeitar ') + singular + ' #' + codigo + '?';
        document.getElementById('dialogoResumo').textContent = selecionada.getAttribute('data-resumo') || '';

        icone.className = 'decisao-icone decisao-icone-' + acao;
        icone.innerHTML = ICONES[acao];

        document.getElementById('dialogoTextoAprovar').hidden = !aprovando;
        document.getElementById('dialogoCampoMotivo').hidden = aprovando;
        motivo.required = !aprovando;
        motivo.disabled = aprovando;
        motivo.value = '';

        caixaAlerta.hidden = !(aprovando && alerta);
        caixaAlerta.textContent = alerta;

        confirmar.className = aprovando ? 'decisao-botao-aprovar' : 'compra-botao-excluir';
        confirmar.textContent = aprovando ? '👍 Aprovar' : '👎 Rejeitar';

        dialogo.showModal();
        (aprovando ? confirmar : motivo).focus();
    }

    if (dialogo) {
        document.getElementById('dialogoCancelar').addEventListener('click', function () {
            dialogo.close();
        });

        // Clicar fora da janela fecha
        dialogo.addEventListener('click', function (evento) {
            if (evento.target === dialogo) dialogo.close();
        });

        // Evita envio duplo
        document.getElementById('dialogoForm').addEventListener('submit', function () {
            document.getElementById('dialogoConfirmar').disabled = true;
        });
    }
})();
