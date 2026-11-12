// Páginas de nova / editar / excluir solicitação de compra (abertas em outra aba)
(function () {
    // "Fechar aba" / "Cancelar": fecha a aba; se o navegador não deixar,
    // volta para a lista de solicitações.
    document.querySelectorAll('[data-fechar-aba]').forEach(function (botao) {
        botao.addEventListener('click', function () {
            window.close();
            setTimeout(function () {
                window.location.href = '/compras';
            }, 150);
        });
    });

    // Linhas de produtos do formulário
    var lista = document.getElementById('listaItens');
    var botaoAdicionar = document.getElementById('botaoAdicionarItem');

    if (!lista || !botaoAdicionar) return;

    // Só deixa remover quando houver mais de um produto
    function atualizarBotoesRemover() {
        var itens = lista.querySelectorAll('.compra-item');
        itens.forEach(function (item) {
            item.querySelector('.compra-remover-item').disabled = itens.length === 1;
        });
    }

    botaoAdicionar.addEventListener('click', function () {
        var novo = lista.querySelector('.compra-item').cloneNode(true);
        novo.querySelector('select').value = '';
        novo.querySelector('input').value = '';
        lista.appendChild(novo);
        atualizarBotoesRemover();
        novo.querySelector('select').focus();
    });

    lista.addEventListener('click', function (evento) {
        var botao = evento.target.closest('.compra-remover-item');
        if (botao && lista.querySelectorAll('.compra-item').length > 1) {
            botao.closest('.compra-item').remove();
            atualizarBotoesRemover();
        }
    });

    atualizarBotoesRemover();
})();
