# PM2

PM2 é descoberto por `pm2 jlist` no contexto do usuário SSH. Exibe aplicação, PID, estado, uptime, restarts e métricas fornecidas pelo PM2. Oferece start/stop/restart/reload e logs sem modo interativo.

Instalações nvm precisam disponibilizar pm2 no PATH de uma sessão SSH não interativa. A plataforma não executa scripts de perfil fornecidos pelo usuário nem aceita JavaScript arbitrário como comando de criação. Novos microsserviços podem ser criados como containers Docker; cadastro de aplicações PM2 novas não faz parte do provisionamento atual.
