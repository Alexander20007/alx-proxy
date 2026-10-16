# ALXMOVIES Proxy

Cloudflare Worker que funciona como gateway unico para os servicos ALXMOVIES.

## Tabela de rotas

| Prefixo | Destino |
|---------|---------|
| alx/* | https://alx-api.onrender.com |
| jney/* | https://api-alex-jney.onrender.com |
| sb-rest/* | Supabase REST |
| sb-auth/* | Supabase Auth |
| sb-fn/* | Supabase Edge Functions |
| sb-storage/* | Supabase Storage |
| canais | Netlify - canais |
| epg | Netlify - programacao |
| release | GitHub - ultima release |

## Desenvolvimento

    npm install
    npm run dev

## Deploy

    npx wrangler login
    npx wrangler deploy

## Secrets

    npx wrangler secret put SUPABASE_PUBLISHABLE_KEY
