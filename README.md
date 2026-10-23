# Mobile Proxy Server

Proxy **HTTP (TCP)** em Python puro (sem dependências), com suporte a HTTPS via `CONNECT`,
autenticação Basic obrigatória, endpoint `/health` e logs sem senhas/tokens.

- Protocolo: **HTTP proxy sobre TCP** (não é SOCKS5, não é UDP).
- Motivo: iPhone e Android só aceitam proxy HTTP nas configurações de Wi-Fi.

## Estrutura
```
mobile-proxy-server/
├── proxy.py          # servidor proxy
├── cloud-init.yaml   # instalação automática na VPS (via navegador)
├── Dockerfile        # opcional
└── README.md
```

## Limitação importante
Um proxy precisa de **IP público + porta TCP aberta**. Hospedagens web (Lovable, Vercel,
Netlify, Render web) só expõem HTTP na porta 443 por domínio — **não servem**.
Use uma **VPS** com IPv4 público: Oracle Cloud Free Tier (grátis), Hetzner, DigitalOcean, Vultr.
Todas podem ser criadas 100% pelo navegador do Android.

## Comando de inicialização
```
PROXY_USER=meuusuario PROXY_PASS='SenhaForte123' PORT=3030 python3 proxy.py
```

## Tutorial pelo navegador do Android (sem Termux/computador)
1. Crie conta no **GitHub** pelo navegador → "New repository" → "Add file > Create new file" →
   nome `proxy.py`, cole o conteúdo, salve. Abra o arquivo, toque em **Raw** e copie a URL.
2. Edite `cloud-init.yaml`: troque `PROXY_USER`, `PROXY_PASS` e a URL raw.
3. Na DigitalOcean (ou Hetzner/Vultr): Create → Droplet → Ubuntu 24.04 → plano mais barato →
   em **Advanced options → Add initialization scripts (User data)** cole o `cloud-init.yaml`.
4. Crie. O painel mostra o **IPv4 público real** do servidor — esse é o seu IP.
5. Se usar firewall do provedor (Cloud Firewall / Security List na Oracle), libere **TCP 3030** de entrada.
6. Após ~2 min, abra no Chrome: `http://SEU_IP:3030/health` → deve mostrar `"status":"ok"`
   e o `public_ip` detectado.
7. Logs: no painel, abra **Console** (terminal web) e rode `journalctl -u mobile-proxy -f`.

### Configurar no Android
Wi-Fi → segure a rede → Editar → Avançado → Proxy: **Manual** → Host: IP real, Porta: 3030.
O Android não tem campo de senha; o Chrome pedirá usuário/senha ao abrir um site.

## Testar no iPhone
Ajustes → Wi-Fi → (i) da rede → **Configurar Proxy → Manual** → Servidor: IP real,
Porta: 3030, **Autenticação: ativada**, usuário e senha. Abra o Safari em
`https://api.ipify.org` — deve aparecer o IP da VPS. Funciona só no Wi-Fi (iOS não
permite proxy manual em dados móveis sem perfil MDM).

## Segurança
- Senha com 12+ caracteres (o servidor recusa iniciar sem isso). Troque-a periodicamente.
- Firewall: só portas 22 e 3030 abertas (`ufw`). Opcional: restrinja 3030 ao seu IP.
- Sites HTTPS continuam criptografados de ponta a ponta (túnel CONNECT).
- A autenticação Basic do proxy trafega **sem criptografia** entre celular e servidor.
  Em redes não confiáveis, prefira uma VPN (WireGuard) na mesma VPS.
- O proxy bloqueia destinos em redes privadas (anti-SSRF).
- Logs registram IP do cliente, método e destino — nunca senhas ou cabeçalhos de autenticação.
