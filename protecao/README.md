# ExpressChat Proteção — servidor

API que guarda as regras de proteção por loja/setor/PC, entrega a configuração
para o agente Windows e recebe heartbeat/relatórios. Autentica o painel reusando
o login do RustDesk (/api/admin/user/current).

- `api/` código Node (Express). `api.tar.gz` é o pacote usado no build.
- `Dockerfile` imagem usada no Easypanel (serviço remoto-protecao).

Variáveis: PORT, DATA_DIR (volume), RUSTDESK_API_BASE (painel interno),
PANEL_ORIGINS (origens liberadas para o painel).
