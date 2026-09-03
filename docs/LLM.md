# Provedores LLM

Em AI → Provedores, informe nome, base_url, modelo, tipo compatível com OpenAI, API key opcional, timeout, max_context e enabled. Base URLs com ou sem /v1 são normalizadas. Testar consulta GET /v1/models; diagnósticos usam POST /v1/chat/completions com resposta JSON validada.

Adicione os CIDRs do serviço a `OUTBOUND_ALLOWED_CIDRS`; isso vale para IP privado e público. O cliente valida todos os endereços DNS e fixa o IP na conexão. Redirects, URL com credencial e endereços de metadata/link-local são bloqueados. TLS não é desabilitado para providers internos: instale a CA corporativa no runtime quando necessário.

Credenciais ficam cifradas. Resposta tem limite de 1 MiB e timeout; contextos usam limites adicionais de linhas/bytes. A API reporta erro de provider, formato inválido ou tool não permitida. Compatibilidade de protocolo foi testada com servidor HTTP de teste; modelos reais precisam de homologação própria.
