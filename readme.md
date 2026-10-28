# lDriver: exploração local de privilégios no Windows via escrita em MSR e cadeia ROP

## Resumo

Este projeto documenta uma prova de conceito (PoC) de escalonamento de privilégios local em ambientes Windows, explorando uma falha de interface entre um processo em modo usuário e um driver kernel. A ideia central é transformar uma primitiva aparentemente simples de escrita em registradores do processador em uma cadeia de execução maliciosa, usando `MSR_LSTAR` como ponto de redirecionamento do fluxo de syscall e uma sequência ROP (Return-Oriented Programming) para controlar o estado do sistema.

A pesquisa é tecnicamente relevante porque mostra que, quando um driver expõe operações privilegiadas de forma insegura, um processo não privilegiado pode, em laboratório, manipular o comportamento do kernel e alterar o caminho de execução da CPU. O foco desta análise está na estrutura da pilha, nas convenções de chamada do ABI x64, na montagem do frame de retorno e na engenharia do fluxo de execução para emular uma transição privilegiada em ambiente controlado.

O objetivo deste material não é promover uso malicioso em produção, mas apresentar uma investigação técnica e educativa sobre como um simples canal de escrita em registradores pode evoluir para um vetor real de escalonamento de privilégios. O código foi escrito como demonstração de laboratório e serve como estudo de caso para segurança de sistemas, engenharia reversa e hardening de drivers.

## 1. Contexto da pesquisa

A separação entre usuário e kernel é um dos pilares fundamentais da arquitetura do Windows. Em nível de hardware, o processador define diferentes modos de execução e o sistema operacional organiza a transição entre esses estados por meio de mecanismos como syscalls, interrupções e registradores específicos do processador. Entre esses registradores, o `MSR_LSTAR` possui papel central, pois aponta para o handler de syscall em modo kernel.

Quando uma aplicação em modo usuário executa uma syscall, o processador transfere o fluxo para o código contido em `MSR_LSTAR`, permitindo que o kernel processe a operação solicitada. O problema é que, se um driver vulnerável ou mal implementado expõe uma interface que aceita escrita em registradores sensíveis do processador, um atacante local pode alterar esse ponteiro e redirecionar a syscall para um alvo arbitrário.

A partir desse ponto, a exploração depende de um conjunto de técnicas de manipulação de execução. Em vez de depender de código novo no kernel, o atacante pode recorrer a gadgets já presentes na imagem do kernel e construir uma cadeia ROP. A ideia é reutilizar pequenos trechos de instruções existentes para controlar a pilha, ajustar registros como `RCX` e `CR4`, e fazer com que o processador execute um fluxo controlado em um contexto privilegiado.

## 2. O problema: escrita em registradores privilegiados

A instrução `WRMSR` permite escrever em um registrador do modelo de processador. Em sistemas modernos, esse tipo de operação é normalmente restrita ao modo kernel. No entanto, quando um driver expõe um canal de IOCTL que encaminha a entrada do usuário para o kernel sem validação suficiente, a primitiva passa a ser acessível a um processo de usuário e deixa de ser uma funcionalidade segura.

No código do PoC, isso é observado no uso de `DeviceIoControl` para abrir e manipular um dispositivo chamado `\\.\CPUZ128`:

- leitura do `MSR_LSTAR`
- cálculo da base do kernel
a partir do valor do handler de syscall
- derivação dos endereços dos gadgets
- escrita em um registrador de syscall para alterar o fluxo

A partir dali, a exploração transforma uma operação aparentemente limitada em um vetor de escalonamento de privilégios. Isso é o que torna o projeto importante: ele não é apenas um experimento isolado, mas uma demonstração de como uma falha local, quando combinada com conhecimento profundo da arquitetura x64, pode resultar em contorno de separação de privilégio.

## 3. A cadeia ROP e o papel dos gadgets

A cadeia ROP é o núcleo da pesquisa. Em vez de injetar código arbitrário no kernel, o atacante usa instruções já presentes na memória do próprio sistema. Essas instruções são chamadas de gadgets, e cada uma executa uma pequena operação útil, como:

- `swapgs ; iretq`
- `mov cr4, rcx ; ret`
- `pop rcx ; ret`
- `swapgs ; sysret ; ret`

Cada gadget cumpre uma finalidade específica:

- `swapgs ; iretq` faz transição de contexto entre usuário e kernel;
- `mov cr4, rcx ; ret` permite escrever um valor em `CR4`;
- `pop rcx ; ret` carrega valores da pilha para `RCX`;
- `swapgs ; sysret ; ret` reconstitui o retorno privilegiado do kernel.

A sequência desses gadgets produz um efeito combinado: desabilita ou reduz restrições de segurança do processador, altera o estado de execução e reencaminha a execução para um caminho controlado. Um ROP chain não é uma “função” em si; ele é uma série de micro-transformações de estado que, juntas, reprogramam o fluxo do sistema.

## 4. Convenções de chamada do ABI x64 e a pilha

Para entender a cadeia de exploração, é crucial compreender as convenções de chamada do ABI x64 da Microsoft. No Windows x64, os primeiros quatro argumentos inteiros são passados por registradores:

- `RCX`
- `RDX`
- `R8`
- `R9`

O restante é empurrado para a pilha. Quando a função recebe mais de quatro argumentos inteiros, os argumentos adicionais devem ser colocados na pilha, preservando o espaço de sombra (shadow space) de 32 bytes reservado pelo chamador antes da chamada. Esse espaço é usado para armazenar argumentos e valores temporários, e mantém a convenção de chamada consistente para funções que recebem mais parâmetros do que os registradores disponíveis. A função chamada retorna o valor em `RAX`, e os registradores não voláteis devem ser preservados pelo callee. Isso é especialmente relevante no assembly usado no projeto, em `rop.asm`.

A rotina `__rop` é definida com esta assinatura:

```asm
__rop PROC
    ; rcx - arg1 (shellcode address)
    ; rdx - arg2 (mov cr4, rcx; ret gadget)
    ; r8  - arg3 (pop rcx; ret gadget)
```

Essa estrutura revela a intenção da exploração. `RCX` aponta para o shellcode; `RDX` carrega o gadget `mov cr4, rcx ; ret`; e `R8` aponta para o gadget `pop rcx ; ret`. A pilha é então montada artificialmente para simular um retorno em contexto privilegiado, e a rotina aproveita a semântica do processador para seu benefício.

A organização da pilha é tão fundamental quanto os próprios gadgets. O código em assembly salva `RFLAGS`, faz alinhamento da stack, monta um frame de retorno e empurra valores em uma ordem precisa para que `IRETQ` e `SYSRET` interpretem corretamente aquelas informações como contexto de execução do kernel.

## 5. Estrutura do frame de retorno e o papel de `IRETQ`

A rotina `rop.asm` é o ponto mais técnico do projeto, porque ela monta um frame artificial de retorno que simula uma transição privilegiada de kernel. O processo inicia com a preservação de `RFLAGS`:

```asm
pushfq
pop r12
```

Depois, o código executa alinhamento da stack:

```asm
sub rsp, 16
xor rbx, rbx
sub rbx, 16
and rsp, rbx
```

Esse alinhamento é essencial, pois instruções como `IRETQ` assumem que a stack está organizada para consumir um contexto de retorno válido. Um stack desalinhada pode causar falha imediata no processo ou impedir corretamente a reconstrução do contexto do processador.

A seguir, o código modifica `RFLAGS` para remover bits de proteção e preparar o estado do processador:

```asm
pushfq
pop rbx
and rbx, 0FFFFFCFFh
or rbx, 40000h
and rbx, 0FFFFFFFFFFFFF9FFh
```

Essa etapa busca controlar o comportamento das flags para aproximar a situação da execução em modo kernel, assumindo uma transição que normalmente seria bloqueada ou invalidada por mecanismos de segurança do processador. O objetivo não é simplesmente “mudar uma flag”: é montar um ambiente de execução compatível com o retorno privilegiado que o sistema espera consumir.

Em seguida, o código empilha os valores que representam o retorno do kernel:

```asm
push rcx
push rdx
push 506f8h
push 18h

mov rax, rsp
add rax, 8h
push rax

push rbx

push 10h

push r8
```

Esse bloco monta o que é essencialmente um mini contexto de CPU. Os valores empilhados reproduzem endereços e seletor de segmento que a instrução `IRETQ` interpreta como parte do estado de retorno. É este ponto que torna a exploração uma engenharia de pilha e não apenas um overwrite simples: o valor da pilha precisa refletir um estado de execução consistente, e a ordem dos pushes é determinante para o resultado.

## 6. Redirecionamento de `MSR_LSTAR` e transição para syscall

O coração da exploração está na manipulação de `MSR_LSTAR`. Esse registrador aponta para o handler do kernel que processa syscalls. Em um ambiente vulnerável, o atacante consegue escrever nele usando uma primitiva de driver e, assim, redirecionar a rotina de syscall para um endereço arbitrário.

O código em C++ faz isso em duas etapas:

1. lê o valor atual de `MSR_LSTAR`;
2. calcula a base do kernel e os endereços dos gadgets;
3. reescreve o registrador para apontar para o gadget `swapgs ; iretq`.

Depois disso, a rotina principal chama `__rop` como se a execução fosse uma transição legítima de syscall:

```cpp
WriteMSR(hDevice, MSR_LSTAR, qGadgetSwapgsIretq);
__rop(shellcode, qGadgetMovCr4Rax, qGadgetPopRcxRet);
```

A instrução `syscall` no assembly, por sua vez, dispara a transição para o handler apontado por `MSR_LSTAR`. Como o registrador foi alterado para uma rota maliciosa, o fluxo não segue a rotina legítima do sistema. Em vez disso, o processador entra em um caminho que começou no kernel, mas foi reorientado por gadgets e stack frame preparados previamente.

## 7. O que a cadeia realmente faz

A sequência de execução combina vários efeitos em um único caminho:

- o processo em modo usuário acessa a interface privilegiada do driver;
- o driver aceita a escrita em `MSR_LSTAR`;
- o valor do registrador é substituído por um endereço malicioso;
- a função `__rop` prepara a stack e os registradores para um retorno em contexto privilegiado;
- a syscall dispara para o gadget `swapgs ; iretq`;
- `CR4` pode ser modificado pela cadeia `mov cr4, rcx ; ret`;
- o shellcode em memória executável é chamado como parte do fluxo de retorno.

Isso é o que torna a técnica tão relevante: ela não depende de um único overwrite, mas de uma composição de vários vetores: abuso de driver, controle da pilha, manipulação de `RSP`, `RFLAGS` e `CR4`, e reutilização de instruções do kernel. O ROP chain é o mecanismo que transforma uma primitiva de escrita em um efeito funcional de escalonamento de privilégios.

## 8. Papel de `CR4` e `RFLAGS` no contexto de segurança do kernel

A manipulação de `CR4` é especialmente importante em qualquer cenário de escalonamento de privilégios em x64. Esse registrador integra vários bits de controle do processador e influencia políticas como SMEP e SMAP, que tentam impedir que instruções em modo kernel executem código controlado por usuário ou que o kernel acesse páginas protegidas em um contexto inadequado.

O gadget:

```asm
mov cr4, rcx ; ret
```

é muito útil para a exploração porque permite que um valor previamente colocado em `RCX` seja movido para `CR4`. Em outras palavras, o atacante pode “reprogramar” o estado de controle do processador para um ambiente mais permissivo. Isso reduz as restrições de segurança que normalmente impediriam o fluxo malicioso de ser executado corretamente.

Já `RFLAGS` determina o estado de interrupções e outros aspectos do comportamento do processador. Ao modular os flags de execução e construir um frame de retorno compatível, o atacante coloca o processador em uma condição muito próxima daquela que ele esperaria em uma execução normal do kernel. Este é um ponto crucial: a exploração não depende de “quebrar” o sistema a toa; ela depende de forçar o processador a interpretar o estado em uma sequência que parece consistente à CPU.

## 9. Limitações e contexto experimental

É importante deixar claro que este projeto é um PoC em ambiente controlado. A exploração depende de múltiplos fatores:

- disponibilidade do driver vulnerável;
- versão específica do Windows;
- offsets estáticos e base conhecida do kernel;
- presença de gadgets compatíveis;
- estabilidade da stack e do contexto de execução;
- permissões locais suficientes para abrir o dispositivo e disparar IOCTLs.

Isso torna o ataque altamente dependente do ambiente alvo. Em outras palavras, o que a demonstração mostra é o princípio e a viabilidade conceitual do vetor, não um exploit universal à prova de falhas. A relevância acadêmica e técnica do projeto está exatamente nisso: entender como as primitivas de kernel podem ser combinadas para constituir um caminho de escalonamento de privilégios.

## 10. O valor científico do projeto

Mesmo sendo um PoC, o projeto tem valor científico e técnico significativo porque ilustra uma classe de vulnerabilidades estruturalmente importante:

- exposição indevida de interfaces privilegiadas;
- falta de validação em operações de driver;
- acesso a registradores sensíveis por processos de usuário;
- reutilização de instruções do kernel via ROP;
- manipulação do fluxo de syscall e do contexto de execução.

Além disso, o estudo demonstra que não é necessário “injetar código novo” em um espaço privilegiado para pressionar a segurança do sistema. Em muitos casos, o atacante consegue usar instruções que já existem, combinadas com um contexto de execução mal construído, para produzir resultados equivalentes aos de um payload tradicional.

Essa observação é central para o entendimento de hardening de kernel e segurança defensiva. A defesa não pode se concentrar apenas em impedir a injeção de shellcode em uma região nova; ela também precisa controlar qualquer fluxo que permita reprogramar a pilha, alterar `MSR_LSTAR` ou depender de gadgets do kernel.

## 11. Considerações de mitigação e defesa

Entre as medidas que reduzem o risco de um cenário como este, destacam-se:

- validação rigorosa de IOCTLs;
- eliminação de acesso direto a registradores de sistema por parte de processos de usuário;
- uso de assinatura e integridade para drivers;
- hardening do kernel para reduzir a disponibilidade de gadgets úteis;
- mitigação de transições de privilégio e controles de execução;
- segmentação rígida do ambiente para execução de testes de segurança.

Esses mecanismos não eliminam a necessidade de desenho seguro, mas reduzem significativamente a superfície de exploração e aumentam a complexidade de qualquer vetor de escalonamento de privilégios local.

## 12. Conclusão

Este repositório apresenta uma prova de conceito de escalonamento de privilégios em Windows baseada na escrita em `MSR_LSTAR` e na construção de uma cadeia ROP. O trabalho mostra como uma falha de driver, quando combinada com entendimento profundo do ABI x64 e da arquitetura do processador, pode transformar uma interface aparentemente limitada em uma rota real para elevação de privilégio.

A importância do projeto não está apenas no código em si, mas na forma como ele conecta conceitos fundamentais de segurança de sistemas:

- separação de privilégios
- transição entre modos de execução
- manipulação da pilha
- controle de fluxo em kernel mode
- engenharia de gadgets e reuso de instruções existentes

Em termos práticos, o estudo reforça que a proteção do kernel não depende apenas da “existência” de bloqueios altos ou de vigilância superficial. Ela exige uma arquitetura de software e hardware em que a manipulação direta de registros críticos e a reinterpretação da stack não sejam tratadas como operações benignas.

O artigo, portanto, funciona como um estudo de caso sobre exploração de kernel em Windows, não para facilitar uso indevido, mas para demonstrar a importância de controles bem definidos, validação estrita de interfaces e hardening contínuo em componentes privilegiados.

---

## Licença e uso responsável

Este material foi publicado apenas para fins de pesquisa acadêmica, estudo técnico e educação em segurança da informação. Não deve ser usado para atacar sistemas de terceiros, explorar vulnerabilidades em produção ou empregar técnicas sem autorização explícita. O uso deve ser restrito a ambientes controlados, isolados e autorizados.
