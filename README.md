# 🔄 Sync StackSpot Knowledge Source Action

[![GitHub Action](https://img.shields.io/badge/GitHub-Action-2088FF?logo=github-actions)](https://github.com/features/actions)
[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?logo=python)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

> **Sincronize automaticamente arquivos locais com um Knowledge Source da StackSpot usando GitHub Actions**

Esta GitHub Action permite manter um Knowledge Source da StackSpot sempre atualizado com os arquivos do seu repositório, fazendo upload de arquivos novos/modificados e removendo arquivos obsoletos automaticamente.

## 📋 **Índice**

- [✨ Features](#-features)
- [🚀 Início Rápido](#-início-rápido)
- [📖 Configuração Detalhada](#-configuração-detalhada)
- [🔧 Inputs](#-inputs)
- [📤 Outputs](#-outputs)
- [💡 Exemplos de Uso](#-exemplos-de-uso)
- [🐛 Troubleshooting](#-troubleshooting)
- [🤝 Contribuindo](#-contribuindo)
- [📄 Licença](#-licença)

## ✨ **Features**

- 🔄 **Sincronização bidirecional**: Upload de arquivos novos/modificados e remoção de obsoletos
- ⚡ **Upload paralelo**: Múltiplos arquivos enviados simultaneamente para melhor performance
- 🔁 **Retry automático**: Tentativas automáticas em caso de falhas temporárias
- 📊 **Relatórios detalhados**: Logs claros e summary no GitHub Actions
- 🎯 **Checksum inteligente**: Só atualiza arquivos que realmente mudaram

## 🚀 **Início Rápido**

```yaml
name: Sync Documentation
on:
  push:
    branches: [main]
    paths:
      - 'docs/**'

jobs:
  sync:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Sync to Knowledge Source
        uses: victorsilvazup/sync-knowledge-source@v1
        with:
          ks_slug: ${{ vars.KS_SLUG }}
          files_dir: ./docs
          client_id: ${{ secrets.STACKSPOT_CLIENT_ID }}
          client_secret: ${{ secrets.STACKSPOT_CLIENT_SECRET }}
          realm: ${{ secrets.STACKSPOT_CLIENT_REALM }}
```

## 📖 **Configuração Detalhada**

### **Pré-requisitos**

1. **Conta StackSpot** com acesso ao Knowledge Source
2. **Service Account** com permissões para gerenciar o Knowledge Source
3. **Knowledge Source** já criado na plataforma

### **Configurando as Credenciais**

1. **Obtenha as credenciais na StackSpot:**
   - Acesse [Documentação StackSpot](https://docs.stackspot.com/home/account/organization/service-credential)

2. **Configure os secrets no GitHub:**
   ```bash
   # No seu repositório, vá em Settings > Secrets and variables > Actions
   # Adicione os seguintes secrets:
   - STACKSPOT_CLIENT_ID
   - STACKSPOT_CLIENT_SECRET
   - STACKSPOT_CLIENT_REALM
   ```

3. **Configure as variáveis:**
   ```bash
   # Em Settings > Secrets and variables > Actions > Variables
   # Adicione:
   - KS_SLUG (identificador do Knowledge Source)
   ```

## 🔧 **Inputs**

| Input | Descrição | Obrigatório | Default | Exemplo |
|-------|-----------|-------------|---------|---------|
| `ks_slug` | Identificador único do Knowledge Source | ✅ | - | `my-docs-ks` |
| `files_dir` | Diretório com os arquivos a sincronizar | ✅ | - | `./docs` |
| `client_id` | Client ID do Service Account | ✅ | - | `${{ secrets.CLIENT_ID }}` |
| `client_secret` | Client Secret do Service Account | ✅ | - | `${{ secrets.CLIENT_SECRET }}` |
| `realm` | Realm de autenticação | ✅ | - | `stackspot` |
| `max_workers` | Número de uploads paralelos | ❌ | `5` | `10` |
| `retry_count` | Tentativas em caso de erro | ❌ | `3` | `5` |

## 📤 **Outputs**

| Output | Descrição | Exemplo |
|--------|-----------|---------|
| `status` | Status da sincronização | `success` ou `error` |
| `files_uploaded` | Quantidade de arquivos enviados | `15` |
| `files_deleted` | Quantidade de arquivos removidos | `3` |
| `local_files_count` | Total de arquivos locais | `42` |

## 💡 **Exemplos de Uso**

### **Sincronização Básica**

```yaml
name: Sync Docs
on:
  push:
    branches: [main]
    paths:
      - 'docs/**'

jobs:
  sync:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - uses: victorsilvazup/sync-knowledge-source@v1
        with:
          ks_slug: docs-ks
          files_dir: ./docs
          client_id: ${{ secrets.STACKSPOT_CLIENT_ID }}
          client_secret: ${{ secrets.STACKSPOT_CLIENT_SECRET }}
          realm: ${{ secrets.STACKSPOT_CLIENT_REALM }}
```

### **Sincronização com Múltiplos Knowledge Sources**

```yaml
name: Sync Multiple KS
on:
  push:
    branches: [main]

jobs:
  sync-docs:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        include:
          - ks_slug: public-docs
            files_dir: ./docs/public
          - ks_slug: internal-docs
            files_dir: ./docs/internal
          - ks_slug: api-docs
            files_dir: ./docs/api
    
    steps:
      - uses: actions/checkout@v4
      
      - name: Sync ${{ matrix.ks_slug }}
        uses: victorsilvazup/sync-knowledge-source@v1
        with:
          ks_slug: ${{ matrix.ks_slug }}
          files_dir: ${{ matrix.files_dir }}
          client_id: ${{ secrets.STACKSPOT_CLIENT_ID }}
          client_secret: ${{ secrets.STACKSPOT_CLIENT_SECRET }}
          realm: ${{ secrets.STACKSPOT_CLIENT_REALM }}
```

## 🐛 **Troubleshooting**

### **Erro: "Variável de ambiente X não definida"**

**Problema:** A action não consegue encontrar uma variável necessária.

**Solução:**
1. Verifique se todos os secrets estão configurados corretamente
2. Confirme que está usando `secrets.` para credenciais e `vars.` para variáveis
3. Verifique a capitalização (case-sensitive)

### **Erro: "Falha na autenticação"**

**Problema:** Cliente não consegue autenticar com a StackSpot.

**Soluções:**
1. Verifique se o Service Account está ativo
2. Confirme que as credenciais estão corretas
3. Verifique se o realm está correto
4. Confirme que o Service Account tem permissões no Knowledge Source

### **Erro: "Diretório não encontrado"**

**Problema:** O diretório especificado não existe.

**Soluções:**
1. Use caminhos relativos ao root do repositório
2. Verifique se o checkout foi feito antes
3. Liste os arquivos para debug:
   ```yaml
   - run: ls -la
   - run: find . -type d -name "docs"
   ```

### **Upload lento ou timeout**

**Problema:** Muitos arquivos ou arquivos grandes causam timeout.

**Soluções:**
1. Aumente o `max_workers` para mais paralelismo
2. Divida em múltiplos jobs se necessário
3. Use `.ksignore` para excluir arquivos desnecessários
4. Configure timeout maior no job:
   ```yaml
   jobs:
     sync:
       timeout-minutes: 30
   ```

### **Arquivos não são atualizados**

**Problema:** Arquivos parecem não ser atualizados no Knowledge Source.

**Soluções:**
1. Verifique se o conteúdo realmente mudou (checksum)
2. Force uma atualização alterando o arquivo
3. Verifique no portal se o KS está processando
4. Aguarde alguns minutos para o processamento

## 📊 **Métricas e Monitoramento**

A action fornece um summary detalhado após cada execução:

Você pode também usar os outputs para criar suas próprias métricas:

```yaml
- name: Save Metrics
  run: |
    echo "sync_date=$(date -u +%Y-%m-%d)" >> $GITHUB_ENV
    echo "files_uploaded=${{ steps.sync.outputs.files_uploaded }}" >> metrics.txt
    echo "files_deleted=${{ steps.sync.outputs.files_deleted }}" >> metrics.txt
```

## 🚀 **Performance**

Para repositórios com muitos arquivos:

1. **Use `.ksignore`** (similar ao `.gitignore`):
   ```
   # .ksignore
   *.tmp
   *.log
   node_modules/
   .git/
   ```

2. **Configure workers baseado no tamanho:**
   - < 100 arquivos: `max_workers: 5` (default)
   - 100-500 arquivos: `max_workers: 10`
   - > 500 arquivos: `max_workers: 20`

3. **Use cache quando possível:**
   ```yaml
   - uses: actions/cache@v4
     with:
       path: ~/.cache/ks-checksums
       key: ${{ runner.os }}-ks-${{ hashFiles('docs/**') }}
   ```

## 🤝 **Contribuindo**

Contribuições são bem-vindas! Por favor:

1. Fork o projeto
2. Crie sua feature branch (`git checkout -b feature/amazing-feature`)
3. Commit suas mudanças (`git commit -m 'Add amazing feature'`)
4. Push para a branch (`git push origin feature/amazing-feature`)
5. Abra um Pull Request

## 🏅 **Licença**

Esse repositório usa a licença [Apache License 2.0](https://github.com/victorsilvazup/sync-knowledge-source/blob/main/LICENSE)