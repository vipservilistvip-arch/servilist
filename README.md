# ServList

Um aplicativo de gerenciamento de servidores com funcionalidades de monitoramento de conectividade e organização de informações de hardware e software.

## Funcionalidades

### Principais
- **Gerenciamento de Servidores**: Cadastre, edite e delete servidores
- **Monitoramento de Conectividade**: Verifique a disponibilidade dos servidores usando ping
- **Organização de Dados**: Armazene informações como IP, sistema operacional, hardware e status
- **Pesquisa**: Filtre servidores por nome, cliente ou IP
- **Status Visual**: Visualize status de servidor (online/offline/manutenção) e backup (sucesso/falha/pendente)
- **Armazenamento Local**: Dados salvos no localStorage do navegador

### Melhorias Implementadas
1. **Proteção de Dados**: Parse seguro de JSON com fallback para dados corrompidos
2. **Acessibilidade**: Botões com aria-label e fechamento do modal com tecla ESC
3. **Performance**: Inicialização lazy do estado para evitar renders extras
4. **Validação**: Tipos TypeScript rigorosos e remoção de 'any'
5. **Conectividade**: Verificação de ping em todos os servidores com indicação visual

## Tecnologias

- **React 19** - Biblioteca de UI
- **TypeScript** - Tipagem estática
- **Tailwind CSS** - Estilização
- **Vite** - Build tool
- **Lucide React** - Ícones

## Scripts

### Desenvolvimento
```bash
npm run dev
```

### Build para Produção
```bash
npm run build
```

### Lint
```bash
npm run lint
```

### Preview do Build
```bash
npm run preview
```

## Uso

1. **Adicionar Servidor**: Clique no botão "Novo Servidor" e preencha os campos
2. **Buscar**: Use o campo de pesquisa para filtrar servidores
3. **Verificar Conectividade**: Clique no botão "Verificar Conexão" para pingar todos os servidores
4. **Editar/Excluir**: Hover sobre um servidor na lista para ver as ações

## Estrutura de Dados

Cada servidor armazena as seguintes informações:
```typescript
interface ServerData {
  id: string;           // UUID único
  name: string;         // Nome do servidor
  client: string;       // Cliente associado
  ip: string;           // Endereço IP
  os: string;           // Sistema operacional
  hardware: string;     // Especificações de hardware
  status: 'online' | 'offline' | 'maintenance';
  backupStatus: 'success' | 'failed' | 'pending';
  lastBackup: string;   // Data do último backup
  notes: string;        // Observações adicionais
}
```

## Armazenamento

Os dados são armazenados no localStorage do navegador com a chave `servlist_servers`. Os dados são carregados automaticamente ao iniciar o aplicativo.

## Roadmap

1. **Testes Automatizados**: Implementar testes com Vitest e Testing Library
2. **Edição de Servidores**: Funcionalidade para editar servidores existentes
3. **Notificações**: Alertas de status via browser notifications
4. **Histórico**: Registro de atividades e histórico de status
5. **Export/Import**: Funcionalidade para exportar/importar dados

## Contribuição

1. Faça um fork do projeto
2. Crie uma branch para sua feature (`git checkout -b feature/nova-funcionalidade`)
3. Commit suas mudanças (`git commit -am 'Adiciona nova funcionalidade'`)
4. Push para a branch (`git push origin feature/nova-funcionalidade`)
5. Crie um Pull Request

## Licença

MIT