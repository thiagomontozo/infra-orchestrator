# Docker Swarm

O adapter usa Docker CLI no host remoto com acesso ao manager. Descobre serviços, nodes e stacks; serviços oferecem inspect, logs, scale e update com force restart. Nodes/stacks de inventário possuem somente ações de consulta. Não há shell nem execução livre de flags.

Logs dependem do driver configurado no cluster. Deploy de stack usa manifesto validado e nome de destino definido pelo recurso. Não há rollback universal de stack ou armazenamento de dados. O conjunto completo de tasks e um painel topológico detalhado ainda não estão implementados; serviços são o foco das operações.
