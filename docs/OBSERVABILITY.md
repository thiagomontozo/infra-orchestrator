# Observabilidade

O dashboard consulta contagens reais de hosts, recursos, operações, aprovações, alertas, incidentes e recomendações. Não injeta amostras em produção. Coletor no worker atualiza inventário periodicamente e aplica regras locais antes de considerar LLM.

Logs usam tail limitado por adapter, com busca local, pausa, download e atualização periódica. Eventos/progresso usam SSE com cursor persistido. O viewer faz polling de janelas limitadas: não há stream infinito de stdout guardado em memória, nem garantia de não perder linhas entre tails. Loki/OpenSearch não são dependências; a integração de consulta com eles ainda requer implementação.

`/metrics` expõe Go/process metrics e contagens do banco para Prometheus. Restrinja o endpoint à rede de observabilidade no proxy. `OTEL_ENABLED=true` habilita exportador OTLP HTTP e spans HTTP/operação/SSH/adapter/LLM. Configure `OTEL_EXPORTER_OTLP_ENDPOINT`. Não há TSDB própria, retenção de métricas históricas ou gráficos históricos sem Prometheus externo.
