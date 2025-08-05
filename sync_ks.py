"""
GitHub Action para sincronização de arquivos com StackSpot Knowledge Source.

Este script sincroniza arquivos locais com um Knowledge Source da StackSpot,
fazendo upload de arquivos novos/modificados e removendo arquivos obsoletos.
"""

import os
import sys

print("🐍 Script Python iniciado!", flush=True)
print(f"📍 Python version: {sys.version}", flush=True)
print(f"📁 Working directory: {os.getcwd()}", flush=True)
print(f"🔍 Script location: {__file__}", flush=True)

try:
    import requests
    print("✅ Módulo 'requests' importado com sucesso", flush=True)
except ImportError as e:
    print(f"❌ Erro ao importar 'requests': {e}", flush=True)
    sys.exit(1)


import json
import logging
import hashlib
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

print("✅ Todos os imports realizados com sucesso", flush=True)

class FlushHandler(logging.StreamHandler):
    def emit(self, record):
        super().emit(record)
        self.flush()

logging.basicConfig(
    level=logging.DEBUG if os.environ.get("RUNNER_DEBUG") == "1" else logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[FlushHandler(sys.stdout)]
)

logger = logging.getLogger(__name__)
logger.info("📊 Sistema de logging configurado")
logger.info("🔍 Verificando variáveis de ambiente...")
env_vars = ["KS_SLUG", "FILES_DIR", "CLIENT_ID", "CLIENT_SECRET", "REALM"]
for var in env_vars:
    value = os.environ.get(var)
    if value:
        if var in ["CLIENT_ID", "CLIENT_SECRET", "REALM"]:
            logger.info(f"✅ {var}: [DEFINIDO - MASCARADO]")
        else:
            logger.info(f"✅ {var}: {value}")
    else:
        logger.error(f"❌ {var}: NÃO DEFINIDO")


@dataclass
class Config:
    """Configuração da aplicação."""
    ks_slug: str
    files_dir: Path
    client_id: str
    client_secret: str
    realm: str
    base_url: str = "https://data-integration-api.stackspot.com"
    idm_url: str = "https://idm.stackspot.com"
    max_workers: int = 5
    chunk_size: int = 8192
    retry_count: int = 3
    retry_backoff: float = 1.0
    timeout: int = 30


@dataclass
class KnowledgeObject:
    """Representa um objeto no Knowledge Source."""
    id: str
    file_path: str
    checksum: str


@dataclass
class SyncResult:
    """Resultado da sincronização."""
    files_uploaded: List[str] = None
    files_deleted: List[str] = None
    
    def __post_init__(self):
        if self.files_uploaded is None:
            self.files_uploaded = []
        if self.files_deleted is None:
            self.files_deleted = []


class APIError(Exception):
    """Exceção customizada para erros de API."""
    pass


class StackSpotClient:
    """Cliente para interagir com a API da StackSpot."""
    
    def __init__(self, config: Config):
        self.config = config
        self.session = self._create_session()
        self._token: Optional[str] = None
    
    def _create_session(self) -> requests.Session:
        """Cria uma sessão HTTP com retry automático."""
        session = requests.Session()
        retry_strategy = Retry(
            total=self.config.retry_count,
            backoff_factor=self.config.retry_backoff,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "POST", "PUT", "DELETE"]
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("https://", adapter)
        return session
    
    @property
    def token(self) -> str:
        """Obtém o token JWT, fazendo autenticação se necessário."""
        if not self._token:
            self._token = self._authenticate()
        return self._token
    
    def _authenticate(self) -> str:
        """Autentica com o serviço e retorna o JWT."""
        logger.info("🔐 Autenticando com StackSpot...")
        
        url = f"{self.config.idm_url}/{self.config.realm}/oidc/oauth/token"
        data = {
            "grant_type": "client_credentials",
            "client_id": self.config.client_id,
            "client_secret": self.config.client_secret
        }
        
        try:
            response = self.session.post(
                url,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                data=data,
                timeout=self.config.timeout
            )
            response.raise_for_status()
            
            token = response.json().get("access_token")
            if not token:
                raise APIError("Token não encontrado na resposta")
            
            logger.info("✅ Autenticação bem-sucedida")
            return token
            
        except requests.exceptions.RequestException as e:
            logger.error(f"❌ Erro na autenticação: {e}")
            raise APIError(f"Falha na autenticação: {e}") from e
    
    def _make_request(self, method: str, endpoint: str, **kwargs) -> requests.Response:
        """Faz uma requisição autenticada à API."""
        url = urljoin(self.config.base_url, endpoint)
        headers = kwargs.get("headers", {})
        headers["Authorization"] = f"Bearer {self.token}"
        kwargs["headers"] = headers
        kwargs["timeout"] = kwargs.get("timeout", self.config.timeout)
        
        try:
            response = self.session.request(method, url, **kwargs)
            response.raise_for_status()
            return response
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 401:
                logger.warning("🔄 Token expirado, reautenticando...")
                self._token = None
                headers["Authorization"] = f"Bearer {self.token}"
                response = self.session.request(method, url, **kwargs)
                response.raise_for_status()
                return response
            raise
    
    def get_knowledge_objects(self) -> List[KnowledgeObject]:
        """Obtém lista de objetos existentes no Knowledge Source."""
        logger.info(f"📋 Buscando objetos existentes em {self.config.ks_slug}...")
        
        endpoint = f"/v1/knowledge-sources/{self.config.ks_slug}/objects"
        response = self._make_request("GET", endpoint)
        
        objects = []
        for obj in response.json():
            objects.append(KnowledgeObject(
                id=obj["id"],
                file_path=obj["file_path"],
                checksum=obj["checksum"]
            ))
        
        logger.info(f"📊 Encontrados {len(objects)} objetos")
        return objects
    
    def upload_file(self, file_path: Path, relative_path: str) -> None:
        """Faz upload de um arquivo para o Knowledge Source."""
        logger.info(f"📤 Iniciando upload de {relative_path}...")
        
        upload_data = self._request_upload_url(relative_path)
        self._upload_to_s3(file_path, upload_data)
        self._process_knowledge_object(upload_data["id"])
        
        logger.info(f"✅ Upload concluído: {relative_path}")
    
    def _request_upload_url(self, file_name: str) -> Dict[str, Any]:
        """Solicita URL pré-assinada para upload."""
        endpoint = "/v2/file-upload/form"
        payload = {
            "file_name": file_name,
            "target_id": self.config.ks_slug,
            "target_type": "KNOWLEDGE_SOURCE",
            "expiration": 600
        }
        
        response = self._make_request(
            "POST", 
            endpoint,
            json=payload,
            headers={"Content-Type": "application/json"}
        )
        return response.json()
    
    def _upload_to_s3(self, file_path: Path, upload_data: Dict[str, Any]) -> None:
        """Faz upload do arquivo para o S3 usando URL pré-assinada."""
        url = upload_data["url"]
        form_data = {k: v for k, v in upload_data["form"].items() if k != "file"}
        
        with open(file_path, "rb") as f:
            files = {"file": f}
            response = self.session.post(
                url,
                data=form_data,
                files=files,
                timeout=300
            )
            response.raise_for_status()
    
    def _process_knowledge_object(self, file_id: str) -> None:
        """Processa o arquivo como knowledge object."""
        endpoint = f"/v1/file-upload/{file_id}/knowledge-objects"
        payload = {
            "split_strategy": "NONE",
            "split_quantity": 500,
            "split_overlap": 50
        }
        
        self._make_request(
            "POST",
            endpoint,
            json=payload,
            headers={"Content-Type": "application/json"}
        )
    
    def delete_object(self, object_id: str) -> None:
        """Remove um objeto do Knowledge Source."""
        endpoint = f"/v1/knowledge-sources/{self.config.ks_slug}/objects/{object_id}"
        self._make_request("DELETE", endpoint)


class FileSynchronizer:
    """Sincroniza arquivos locais com Knowledge Source."""
    
    def __init__(self, config: Config, client: StackSpotClient):
        self.config = config
        self.client = client
    
    def calculate_checksum(self, file_path: Path) -> str:
        """Calcula o checksum SHA256 de um arquivo."""
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(self.config.chunk_size), b""):
                sha256_hash.update(chunk)
        return sha256_hash.hexdigest()
    
    def get_local_files(self) -> Dict[str, Path]:
        """Obtém mapa de arquivos locais."""
        files = {}
        for file_path in self.config.files_dir.rglob("*"):
            if file_path.is_file():
                relative_path = str(file_path.relative_to(self.config.files_dir))
                relative_path = relative_path.replace("\\", "/")
                files[relative_path] = file_path
        
        logger.info(f"📁 Encontrados {len(files)} arquivos locais")
        return files
    
    def sync(self) -> SyncResult:
        """Executa a sincronização completa e retorna o resultado."""
        logger.info("🚀 Iniciando sincronização...")
        result = SyncResult()
    
        remote_objects = {obj.file_path: obj for obj in self.client.get_knowledge_objects()}
        local_files = self.get_local_files()
        
        to_upload = []
        to_delete = []
        
        for rel_path, file_path in local_files.items():
            checksum = self.calculate_checksum(file_path)
            remote_obj = remote_objects.get(rel_path)
            
            if remote_obj:
                if remote_obj.checksum == checksum:
                    logger.info(f"✔️ {rel_path} está atualizado")
                else:
                    logger.info(f"🔄 {rel_path} precisa ser atualizado")
                    to_upload.append((file_path, rel_path))
            else:
                logger.info(f"➕ {rel_path} é novo")
                to_upload.append((file_path, rel_path))
        
        for rel_path, obj in remote_objects.items():
            if rel_path not in local_files:
                logger.info(f"➖ {rel_path} será removido")
                to_delete.append((rel_path, obj.id))
        
        if to_upload:
            logger.info(f"📤 Fazendo upload de {len(to_upload)} arquivo(s)...")
            uploaded = self._parallel_upload(to_upload)
            result.files_uploaded = uploaded
        
        if to_delete:
            logger.info(f"🗑️ Removendo {len(to_delete)} arquivo(s) obsoleto(s)...")
            deleted = []
            for rel_path, obj_id in to_delete:
                try:
                    self.client.delete_object(obj_id)
                    logger.info(f"✅ Removido: {rel_path}")
                    deleted.append(rel_path)
                except Exception as e:
                    logger.error(f"❌ Erro ao remover {rel_path}: {e}")
            result.files_deleted = deleted
        
        logger.info("✨ Sincronização concluída!")
        return result
    
    def _parallel_upload(self, files: List[Tuple[Path, str]]) -> List[str]:
        """Faz upload de múltiplos arquivos em paralelo e retorna lista de sucesso."""
        uploaded = []
        with ThreadPoolExecutor(max_workers=self.config.max_workers) as executor:
            futures = {}
            for file_path, rel_path in files:
                future = executor.submit(self.client.upload_file, file_path, rel_path)
                futures[future] = rel_path
            
            for future in as_completed(futures):
                rel_path = futures[future]
                try:
                    future.result()
                    uploaded.append(rel_path)
                except Exception as e:
                    logger.error(f"❌ Erro no upload de {rel_path}: {e}")
        
        return uploaded


def load_config() -> Config:
    """Carrega configuração a partir das variáveis de ambiente."""
    def get_env(var_name: str, default: Optional[str] = None) -> str:
        value = os.environ.get(var_name, default)
        if value is None:
            logger.error(f"❌ Variável de ambiente {var_name} não definida")
            sys.exit(1)
        return value
    
    return Config(
        ks_slug=get_env("KS_SLUG"),
        files_dir=Path(get_env("FILES_DIR")),
        client_id=get_env("CLIENT_ID"),
        client_secret=get_env("CLIENT_SECRET"),
        realm=get_env("REALM"),
        max_workers=int(get_env("MAX_WORKERS", "5")),
        retry_count=int(get_env("RETRY_COUNT", "3"))
    )


def write_github_outputs(result: SyncResult, local_files_count: int) -> None:
    """Escreve outputs para GitHub Actions."""
    if not os.environ.get("GITHUB_ACTIONS"):
        logger.info("📝 Não está rodando no GitHub Actions, pulando outputs")
        return
    
    output_file = os.environ.get("GITHUB_OUTPUT")
    if output_file:
        logger.info(f"📝 Escrevendo outputs em {output_file}")
        try:
            with open(output_file, "a") as f:
                f.write(f"status=success\n")
                f.write(f"files_uploaded={len(result.files_uploaded)}\n")
                f.write(f"files_deleted={len(result.files_deleted)}\n")
                f.write(f"local_files_count={local_files_count}\n")
            logger.info("✅ Outputs escritos com sucesso")
        except Exception as e:
            logger.error(f"❌ Erro ao escrever outputs: {e}")
    else:
        logger.warning("⚠️ GITHUB_OUTPUT não definido")


def write_github_summary(result: SyncResult, local_files_count: int) -> None:
    """Escreve summary para GitHub Actions."""
    if not os.environ.get("GITHUB_ACTIONS"):
        return
    
    summary_file = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_file:
        try:
            with open(summary_file, "a") as f:
                f.write("## 📊 Resultado da Sincronização\n\n")
                f.write(f"- ✅ **Status**: Sucesso\n")
                f.write(f"- 📤 **Arquivos enviados**: {len(result.files_uploaded)}\n")
                f.write(f"- 🗑️ **Arquivos removidos**: {len(result.files_deleted)}\n")
                f.write(f"- 📁 **Total de arquivos locais**: {local_files_count}\n\n")
                
                if result.files_uploaded:
                    f.write("### 📤 Arquivos Enviados\n")
                    for file in result.files_uploaded[:10]:
                        f.write(f"- `{file}`\n")
                    if len(result.files_uploaded) > 10:
                        f.write(f"- _...e mais {len(result.files_uploaded) - 10} arquivos_\n")
                    f.write("\n")
                
                if result.files_deleted:
                    f.write("### 🗑️ Arquivos Removidos\n")
                    for file in result.files_deleted[:10]:
                        f.write(f"- `{file}`\n")
                    if len(result.files_deleted) > 10:
                        f.write(f"- _...e mais {len(result.files_deleted) - 10} arquivos_\n")
        except Exception as e:
            logger.error(f"❌ Erro ao escrever summary: {e}")


def main() -> None:
    """Função principal."""
    start_time = time.time()
    
    try:
        logger.info("=" * 60)
        logger.info("🚀 INICIANDO SINCRONIZAÇÃO COM KNOWLEDGE SOURCE")
        logger.info("=" * 60)
        config = load_config()
        logger.info(f"📋 Knowledge Source: {config.ks_slug}")
        logger.info(f"📁 Diretório: {config.files_dir}")
        
        if not config.files_dir.exists():
            error_msg = f"Diretório não encontrado: {config.files_dir}"
            logger.error(f"❌ {error_msg}")
            
            if os.environ.get("GITHUB_ACTIONS"):
                print(f"::error::{error_msg}")
                output_file = os.environ.get("GITHUB_OUTPUT")
                if output_file:
                    with open(output_file, "a") as f:
                        f.write("status=error\n")
                        f.write("files_uploaded=0\n")
                        f.write("files_deleted=0\n")
                        f.write("local_files_count=0\n")
            
            sys.exit(1)

        logger.info("🔧 Inicializando cliente StackSpot...")
        client = StackSpotClient(config)
        
        logger.info("🔧 Inicializando sincronizador...")
        synchronizer = FileSynchronizer(config, client)
        
        local_files = synchronizer.get_local_files()
        local_files_count = len(local_files)

        result = synchronizer.sync()
        
        elapsed_time = time.time() - start_time
        
        logger.info("=" * 60)
        logger.info("✅ SINCRONIZAÇÃO CONCLUÍDA COM SUCESSO!")
        logger.info(f"⏱️  Tempo total: {elapsed_time:.2f} segundos")
        logger.info(f"📤 Arquivos enviados: {len(result.files_uploaded)}")
        logger.info(f"🗑️  Arquivos removidos: {len(result.files_deleted)}")
        logger.info(f"📁 Total de arquivos locais: {local_files_count}")
        logger.info("=" * 60)
        
        write_github_outputs(result, local_files_count)
        write_github_summary(result, local_files_count)
        
        if os.environ.get("GITHUB_ACTIONS"):
            if result.files_uploaded:
                print(f"::notice::📤 {len(result.files_uploaded)} arquivo(s) enviado(s) com sucesso")
            if result.files_deleted:
                print(f"::notice::🗑️ {len(result.files_deleted)} arquivo(s) removido(s)")
        
    except APIError as e:
        logger.error(f"❌ Erro de API: {e}")
        if os.environ.get("GITHUB_ACTIONS"):
            print(f"::error::Erro de API: {e}")
            output_file = os.environ.get("GITHUB_OUTPUT")
            if output_file:
                with open(output_file, "a") as f:
                    f.write("status=error\n")
                    f.write("files_uploaded=0\n")
                    f.write("files_deleted=0\n")
                    f.write(f"local_files_count={locals().get('local_files_count', 0)}\n")
        sys.exit(1)
        
    except Exception as e:
        logger.error(f"❌ Erro inesperado: {e}")
        logger.exception("Detalhes do erro:")
        if os.environ.get("GITHUB_ACTIONS"):
            print(f"::error::Erro inesperado: {e}")
            output_file = os.environ.get("GITHUB_OUTPUT")
            if output_file:
                with open(output_file, "a") as f:
                    f.write("status=error\n")
                    f.write("files_uploaded=0\n")
                    f.write("files_deleted=0\n")
                    f.write(f"local_files_count={locals().get('local_files_count', 0)}\n")
        sys.exit(1)


if __name__ == "__main__":
    main()