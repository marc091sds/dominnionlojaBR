// Função segura do painel DOMINNION.
// Compatível com o _lib.js e com o admin.html deste projeto.
// A senha deve ficar somente na variável ADMIN_SENHA do Netlify.
const crypto = require('crypto');
const { J, st, lerProdutos, salvarProduto, removerProduto, lerSite, salvarSite } = require('./_lib');

const RES = (status, data) => {
  const r = J(status, data);
  r.headers = { ...(r.headers || {}), 'Cache-Control': 'no-store, max-age=0' };
  return r;
};
const senhaConfigurada = () => String(process.env.ADMIN_SENHA || '');
const chave = () => crypto.createHash('sha256').update('dominnion-admin|' + senhaConfigurada()).digest();
const assinar = () => {
  const p = Buffer.from(JSON.stringify({ exp: Date.now() + 12 * 3600e3 })).toString('base64url');
  return p + '.' + crypto.createHmac('sha256', chave()).update(p).digest('base64url');
};
const iguais = (a, b) => {
  const x = Buffer.from(String(a == null ? '' : a));
  const y = Buffer.from(String(b == null ? '' : b));
  return x.length === y.length && crypto.timingSafeEqual(x, y);
};
const tokenOk = token => {
  const [p, sig] = String(token || '').split('.');
  if (!p || !sig) return false;
  const esperado = crypto.createHmac('sha256', chave()).update(p).digest('base64url');
  if (!iguais(sig, esperado)) return false;
  try { return JSON.parse(Buffer.from(p, 'base64url').toString()).exp > Date.now(); }
  catch (_) { return false; }
};
const num = (v, padrao = 0) => {
  const n = Number(String(v == null ? '' : v).replace(',', '.'));
  return Number.isFinite(n) && n >= 0 ? n : padrao;
};
const txt = (v, limite = 200) => String(v == null ? '' : v).trim().slice(0, limite);
const slug = s => txt(s, 80).normalize('NFD').replace(/[\u0300-\u036f]/g, '').toLowerCase()
  .replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 40) || 'produto';
const fotoValida = s => /^(img\/[\w.\-]+|\/.netlify\/functions\/foto\?k=[a-z0-9]+\.jpg)$/.test(s);

function limparProduto(p) {
  p = p && typeof p === 'object' ? p : {};
  const nome = txt(p.nome, 80);
  if (!nome) throw new Error('Informe o nome do produto.');
  const preco = num(p.preco, -1);
  if (!(preco > 0)) throw new Error('Informe um preço válido.');
  const id = /^[a-z0-9-]{1,60}$/.test(String(p.id || ''))
    ? String(p.id) : slug(nome) + '-' + Date.now().toString(36).slice(-5);
  const imagens = (Array.isArray(p.imagens) ? p.imagens : [])
    .map(x => txt(x, 300)).filter(fotoValida).slice(0, 3);
  return {
    id, nome, linha: txt(p.linha, 60) || 'Outros', cat: txt(p.cat, 40) || 'Bonés',
    cor: txt(p.cor, 30), aba: txt(p.aba, 20) || 'Curva', preco,
    precoDe: num(p.precoDe), precoPromo: 0,
    badge: ['NOVO', 'OFERTA', 'MAIS VENDIDO'].includes(p.badge) ? p.badge : '',
    descricao: txt(p.descricao, 300), estoque: Math.floor(num(p.estoque)),
    destaque: !!p.destaque, ativo: p.ativo !== false,
    peso: num(p.peso, 0.25) || 0.25, largura: num(p.largura, 20) || 20,
    altura: num(p.altura, 12) || 12, comprimento: num(p.comprimento, 25) || 25,
    imagens
  };
}

async function login(ev, senhaRecebida) {
  const senha = senhaConfigurada();
  if (senha.length < 10) {
    return RES(500, { erro: 'Configure ADMIN_SENHA no Netlify com pelo menos 10 caracteres.' });
  }

  // O bloqueio de tentativas usa Blobs, mas uma indisponibilidade temporária
  // desse registro não impede a validação da senha correta.
  let seg = null;
  try {
    seg = st(ev, 'seg');
    const falhas = (await seg.get('falhas', { type: 'json' })) || { n: 0, ate: 0 };
    if (falhas.ate > Date.now()) return RES(429, { erro: 'Muitas tentativas. Aguarde 15 minutos.' });
  } catch (err) { console.error('admin login throttle:', err.message); }

  if (!iguais(senhaRecebida, senha)) {
    if (seg) {
      try {
        let f = (await seg.get('falhas', { type: 'json' })) || { n: 0, ate: 0 };
        f.n = (f.n || 0) + 1;
        if (f.n >= 5) f = { n: 0, ate: Date.now() + 15 * 60e3 };
        await seg.setJSON('falhas', f);
      } catch (err) { console.error('admin login falhas:', err.message); }
    }
    await new Promise(resolve => setTimeout(resolve, 500));
    return RES(401, { erro: 'Senha incorreta.' });
  }

  if (seg) {
    try { await seg.setJSON('falhas', { n: 0, ate: 0 }); }
    catch (err) { console.error('admin login reset:', err.message); }
  }
  return RES(200, { token: assinar() });
}

exports.handler = async ev => {
  if (ev.httpMethod !== 'POST') return RES(405, { erro: 'Método inválido.' });
  try {
    const body = JSON.parse(ev.body || '{}');
    if (body.acao === 'login') return await login(ev, body.senha);

    const headers = ev.headers || {};
    const authorization = headers.authorization || headers.Authorization || '';
    if (senhaConfigurada().length < 10 || !tokenOk(String(authorization).replace(/^Bearer\s+/i, ''))) {
      return RES(401, { erro: 'Sessão expirada. Entre novamente.' });
    }

    switch (body.acao) {
      case 'listar':
        return RES(200, { produtos: await lerProdutos(ev) });

      case 'salvar': {
        const produto = limparProduto(body.produto);
        await salvarProduto(ev, produto);
        return RES(200, { produto });
      }

      case 'excluir': {
        const id = String(body.id || '');
        if (!/^[a-z0-9-]{1,60}$/.test(id)) throw new Error('Produto inválido.');
        await removerProduto(ev, id);
        return RES(200, { ok: true });
      }

      case 'upload': {
        const dados = String(body.dados || '');
        if (!dados || dados.length > 2.2e6) throw new Error('Foto muito grande.');
        const buffer = Buffer.from(dados, 'base64');
        if (buffer.length < 100 || buffer[0] !== 0xff || buffer[1] !== 0xd8) throw new Error('Envie uma foto JPG.');
        const key = Date.now().toString(36) + crypto.randomBytes(4).toString('hex') + '.jpg';
        await st(ev, 'fotos').set(key, buffer.buffer.slice(buffer.byteOffset, buffer.byteOffset + buffer.length));
        return RES(200, { url: '/.netlify/functions/foto?k=' + key });
      }

      case 'pedidos': {
        const pedidos = st(ev, 'pedidos');
        const { blobs } = await pedidos.list();
        const keys = (blobs || []).map(item => item.key).sort().reverse().slice(0, 60);
        const lista = (await Promise.all(keys.map(key => pedidos.get(key, { type: 'json' })))).filter(Boolean);
        return RES(200, { pedidos: lista });
      }

      case 'pedido': {
        const ref = String(body.ref || '');
        if (!/^DOM-[A-Z0-9]+$/.test(ref)) throw new Error('Pedido inválido.');
        const pedidos = st(ev, 'pedidos');
        const pedido = await pedidos.get(ref, { type: 'json' });
        if (!pedido) throw new Error('Pedido não encontrado.');
        pedido.enviado = !!body.enviado;
        pedido.rastreio = txt(body.rastreio, 40);
        await pedidos.setJSON(ref, pedido);
        return RES(200, { ok: true });
      }

      case 'site_ler': {
        return RES(200, { site: await lerSite(ev) });
      }

      case 'site_salvar': {
        const site = body.site;
        if (!site || typeof site !== 'object' || Array.isArray(site)) throw new Error('Dados da página inválidos.');
        if (JSON.stringify(site).length > 500000) throw new Error('Os dados da página estão muito grandes.');
        const novo = { ...site };
        if (Array.isArray(novo.feedbacks)) {
          novo.feedbacks = novo.feedbacks.map(x => txt(x, 300)).filter(fotoValida).slice(0, 8);
        } else novo.feedbacks = [];
        if (novo.feed_t != null) novo.feed_t = txt(novo.feed_t, 60);
        if (novo.feed_s != null) novo.feed_s = txt(novo.feed_s, 160);
        if (!novo.secoes || typeof novo.secoes !== 'object' || Array.isArray(novo.secoes)) novo.secoes = {};
        novo.secoes = { ...novo.secoes, feed: novo.secoes.feed !== false };
        await salvarSite(ev, novo);
        return RES(200, { site: novo });
      }

      case 'diag': {
        let erro = '';
        try { await st(ev, 'loja').get('iniciado'); }
        catch (err) { erro = err.message || 'Falha ao acessar o armazenamento.'; }
        return RES(200, {
          armazenamento: !erro, erro,
          pagamento: !!process.env.MP_ACCESS_TOKEN,
          frete: !!process.env.CEP_ORIGEM && !!(process.env.SF_TOKEN || process.env.ME_TOKEN)
        });
      }

      default:
        return RES(400, { erro: 'Ação inválida.' });
    }
  } catch (err) {
    console.error('admin:', err && err.message);
    return RES(400, { erro: err && err.message ? err.message : 'Não foi possível concluir a operação.' });
  }
};
