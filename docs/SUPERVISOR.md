# Supervisor

`supervisorctl status` fornece processos e estado. Start, stop, restart, status e tail de logs têm argumentos construídos pelo adapter. Use configuração local de supervisorctl acessível ao usuário SSH; não publique sua interface XML-RPC desprotegida.

Somente nomes de processos inventariados podem ser alvos. Log tail e tratamento de nomes/grupos têm testes de parser/construção; a autorização do daemon precisa ser validada no host real.
