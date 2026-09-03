# Bastion

Cadastre primeiro o bastion como host normal, com chave própria e fingerprint confirmada. No destino privado, selecione esse host em Bastion e informe a credencial e fingerprint do destino. O worker valida separadamente as duas identidades e abre `direct-tcpip` pelo bastion.

Habilite somente os encaminhamentos necessários no sshd do bastion; restrinja destino/porta com `PermitOpen` quando possível. O IP resolvido do destino também precisa pertencer a `OUTBOUND_ALLOWED_CIDRS`. O worker resolve DNS antes de encaminhar, evitando resolver para um destino diferente no bastion.

Um bastion pode atender vários destinos. Esta versão admite um salto, sem cadeias recursivas. A obtenção automática da fingerprint de um destino inacessível diretamente não atravessa o bastion; obtenha-a por console confiável e cole no cadastro. Os testes de protocolo validam SSH; a validação de uma topologia bastion real deve ser feita no ambiente de implantação.
