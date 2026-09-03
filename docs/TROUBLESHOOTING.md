# Troubleshooting

| Sintoma | Verificação |
|---|---|
| Login falha em HTTP | APP_ENV production exige HTTPS/cookies Secure; use origem correta |
| CSRF rejected | PUBLIC_ORIGIN, cookie io_csrf e X-CSRF-Token devem corresponder |
| Host bloqueado | CIDR permitido, DNS resolvido, porta e fingerprint confirmada |
| Chave inválida | Use PEM/OpenSSH suportado; chaves com passphrase precisam de agent |
| Docker indisponível | daemon remoto ativo e usuário autorizado ao socket |
| Operação waiting_approval | Outro usuário APPROVER/ADMIN precisa revisar |
| Operação timeout e recurso bloqueado | Verifique efeito remoto e use reconciliação administrativa |
| kubectl não encontrado | PATH não interativo do usuário SSH e kubeconfig configurado |
| LLM provider inacessível | URL, CIDR, TLS/CA, modelo, enabled e token |
| Logs vazios | driver/journald/permissões, tail e estado do recurso |
| Scheduler sem disparo | timezone, enabled, usuário/permissões, schedule_runs e conexão DB |

Não ignore host key, TLS, MFA ou policy para diagnosticar. Use logs estruturados com request_id e auditoria; não inclua secrets em issues públicas. Informe versões, erro sanitizado e passos reproduzíveis.
