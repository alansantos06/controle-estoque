
document.addEventListener('DOMContentLoaded', () => {
    const sidebar = document.getElementById('sidebar');
    const menuBotao = document.getElementById('menuBotao');
    const temaBotao = document.getElementById('temaBotao');
    const temaIcone = document.getElementById('temaIcone');
    const temaTexto = document.getElementById('temaTexto');

    // Abre e fecha o menu lateral.
    if (sidebar && menuBotao) {
        menuBotao.addEventListener('click', () => {
            const aberto = sidebar.classList.toggle('aberto');
            menuBotao.setAttribute('aria-expanded', String(aberto));
        });

        document.addEventListener('click', (evento) => {
            const clicouNoMenu = sidebar.contains(evento.target);
            const clicouNoBotao = menuBotao.contains(evento.target);

            if (!clicouNoMenu && !clicouNoBotao) {
                sidebar.classList.remove('aberto');
                menuBotao.setAttribute('aria-expanded', 'false');
            }
        });
    }

    // Aplica o tema claro ou escuro.
    function aplicarTema(tema) {
        document.documentElement.setAttribute('data-theme', tema);

        if (temaIcone) {
            temaIcone.textContent = tema === 'dark' ? '☀️' : '🌙';
        }

        if (temaTexto) {
            temaTexto.textContent = tema === 'dark'
                ? 'Modo claro'
                : 'Modo escuro';
        }
    }

    const temaSalvo = localStorage.getItem('tema-estoque') || 'light';
    aplicarTema(temaSalvo);

    if (temaBotao) {
        temaBotao.addEventListener('click', () => {
            const temaAtual = document.documentElement.getAttribute('data-theme');
            const novoTema = temaAtual === 'dark' ? 'light' : 'dark';

            aplicarTema(novoTema);
            localStorage.setItem('tema-estoque', novoTema);
        });
    }
});
