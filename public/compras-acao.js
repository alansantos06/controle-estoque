// Telas de nova / editar solicitação de compra
(function () {
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
