# Deployments

Deployments registram versão, artefato, commit, ambiente, operador, operation_id e status. O formulário recebe manifesto e alvo inventariado. O conteúdo é cifrado; a operação transporta referência e hash. O adapter valida nome/kind/namespace antes de chamar Compose, kubectl, Swarm ou Nomad.

Compose requer projeto/arquivo existente no host; Kubernetes e Nomad recebem documento JSON compatível. Swarm usa stack com nome definido. O status acompanha a operação. Criação de um container Docker novo por imagem utiliza o fluxo dedicado de provisionamento.

Rollback só aparece onde há mecanismo conhecido: histórico de rollout kubectl ou snapshot nativo Kubernetes disponível. Snapshot restaura spec, não dados persistidos. Não se afirma rollback para Compose, Nomad ou Swarm sem estado anterior suficiente. Registre digest/commit imutável e valide compatibilidade de schema e dados antes de reverter.
