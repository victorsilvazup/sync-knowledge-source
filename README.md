# Sync Knowledge Source GitHub Action

Esta Action sincroniza arquivos locais com um Knowledge Source da StackSpot. Ela realiza:

- Upload de arquivos novos ou modificados
- Remoção de objetos que não existem mais localmente
- Detecção de alterações via checksum
- Upload utilizando a API da StackSpot

## Inputs

| Nome           | Descrição                                      | Obrigatório |
|----------------|------------------------------------------------|-------------|
| `ks_slug`      | Slug do Knowledge Source                       | ✅           |
| `files_dir`    | Caminho para o diretório com os arquivos       | ✅           |
| `client_id`    | Client ID para autenticação                    | ✅           |
| `client_secret`| Client Secret para autenticação                | ✅           |
| `realm`        | Realm usado na autenticação                    | ✅           |

## Exemplo de uso

```yaml
jobs:
  sync:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Sync KS
        uses: victorsilvazup/sync-knowledge-source@v1
        with:
          ks_slug: my-knowledge-source
          files_dir: ./ks-files
          client_id: ${{ secrets.STACKSPOT_CLIENT_ID }}
          client_secret: ${{ secrets.STACKSPOT_CLIENT_SECRET }}
          realm: ${{ secrets.STACKSPOT_CLIENT_REALM }}
