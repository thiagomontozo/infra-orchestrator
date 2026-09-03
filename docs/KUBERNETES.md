# Kubernetes

Há dois transportes reais: kubectl já configurado no host SSH e API HTTPS com kubeconfig cadastrado em Kubernetes → Adicionar cluster. O kubeconfig é cifrado e nunca reapresentado ao navegador. O parser admite token ou certificado/chave incorporados e CA incorporada; rejeita arquivos locais, plugins exec/auth-provider e `insecure-skip-tls-verify`. Use uma identidade de serviço restrita por namespace, sem cluster-admin por padrão.

A API descobre namespaces, nodes, deployments, statefulsets, daemonsets, pods, services, jobs e cronjobs. Oferece consultas, eventos, logs de pods, restart, scale, delete de pod e aplicação de manifesto validado para o recurso alvo. Kubectl remoto também oferece rollout status/history e undo. Cadastro de kubeconfig não permite comandos arbitrários.

O transporte HTTPS guarda snapshots cifrados antes de alterações de workloads e pode reaplicar a spec anterior. Rollback exige snapshot existente e revisão 0 (último snapshot); não representa restauração de volumes ou dados externos. O transporte kubectl depende do histórico de rollout retido pelo cluster. Aplicações sem histórico não têm rollback garantido.

Manifestos de deploy precisam corresponder a kind, nome e namespace do recurso. Não é um console Kubernetes genérico nem um substituto para RBAC do cluster. Configurações de exec providers de nuvem requerem token/certificado de serviço compatível ou kubectl remoto administrado.
