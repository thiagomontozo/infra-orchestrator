# GitOps

O módulo permite observar um manifesto por URL HTTPS e comparar conteúdo com a observação anterior. O endpoint de diff usa a mesma política de saída/limite de bytes e não segue redirects. O operador revisa o diff e submete o conteúdo pelo fluxo de deployment/aprovação.

Esta é uma fundação de observação e revisão, sem reconciliador contínuo de desired state, clone autenticado de repositórios ou remoção automática de recursos ausentes. URLs raw imutáveis por commit são preferíveis. Uma URL de manifesto não equivale a verificar assinatura de commit. Nenhuma alteração é executada apenas porque o conteúdo remoto mudou.
