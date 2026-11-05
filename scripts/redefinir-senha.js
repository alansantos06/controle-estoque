// Uso: node scripts/redefinir-senha.js email@exemplo.com NovaSenha123
// Redefine a senha de um usuário direto pelo Supabase (requer SUPABASE_SECRET_KEY no .env).

const path = require('path');
require('dotenv').config({ path: path.join(__dirname, '..', '.env') });

const { supabaseAdmin } = require('../supabase');

async function main() {
    const [email, novaSenha] = process.argv.slice(2);

    if (!email || !novaSenha) {
        console.log('Uso: node scripts/redefinir-senha.js <email> <nova-senha>');
        process.exitCode = 1;
        return;
    }

    if (novaSenha.length < 6) {
        console.log('A senha precisa ter pelo menos 6 caracteres.');
        process.exitCode = 1;
        return;
    }

    const emailNormalizado = email.trim().toLowerCase();
    let usuario = null;

    for (let pagina = 1; !usuario; pagina++) {
        const { data, error } = await supabaseAdmin.auth.admin.listUsers({
            page: pagina,
            perPage: 1000
        });

        if (error) {
            console.error('Erro ao buscar usuários:', error.message);
            process.exitCode = 1;
            return;
        }

        usuario = data.users.find(
            (u) => u.email?.toLowerCase() === emailNormalizado
        );

        if (data.users.length < 1000) break;
    }

    if (!usuario) {
        console.log(`Nenhum usuário encontrado com o e-mail ${email}.`);
        process.exitCode = 1;
        return;
    }

    const { error } = await supabaseAdmin.auth.admin.updateUserById(
        usuario.id,
        { password: novaSenha }
    );

    if (error) {
        console.error('Erro ao redefinir a senha:', error.message);
        process.exitCode = 1;
        return;
    }

    console.log(`Senha de ${usuario.email} redefinida com sucesso.`);
}

main().catch((erro) => {
    console.error("Erro inesperado:", erro);
    process.exitCode = 1;
});
