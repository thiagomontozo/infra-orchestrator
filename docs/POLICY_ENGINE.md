# Policy Engine

Regras combinam environment, action, role, user_id, host_id, group, resource_id e risk. Campos vazios não restringem o match. `deny` prevalece; `approval_required` e `require_mfa` são cumulativos. Uma janela fora do horário nega a operação.

```json
{"name":"Produção exige MFA","environment":"production","data":{"action":"*","require_mfa":true,"approval_required":true}}
```

```json
{"name":"Restart controlado staging","environment":"staging","data":{"action":"restart","allow_agent":true,"approval_required":false}}
```

O default de produção sempre requer aprovação humana para mutações, inclusive ações de agentes. `ASSISTED` sempre exige aprovação. `ADVISORY`/`DISABLED` nunca podem mutar. `AUTOMATED_POLICY_CONTROLLED` exige regra explícita `allow_agent`; o monitor também limita a três solicitações por recurso/hora.

Janelas usam dias 0..6 (domingo..sábado), início/fim HH:MM e timezone IANA. Sábado 22:00–02:00 inclui domingo até 02:00, usando o dia de início da janela.

```json
{"window":{"days":[6],"start":"22:00","end":"02:00","timezone":"America/Sao_Paulo"}}
```

Cadastros em Maintenance Windows servem de referência; associe os mesmos valores ao campo `window` da regra. Regras são relidas tanto na submissão quanto antes da execução. Aprovação histórica não permite ignorar políticas novas.
