"""
GitHub Action para sincronização de arquivos com StackSpot Knowledge Source.

Este script sincroniza arquivos locais com um Knowledge Source da StackSpot,
fazendo upload de arquivos novos/modificados e removendo arquivos obsoletos.
"""

import os
import sys
import json
import logging
import hashlib
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin

import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)


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
        return
    
    output_file = os.environ.get("GITHUB_OUTPUT")
    if output_file:
        with open(output_file, "a") as f:
            f.write(f"status={result.status}\n")
            f.write(f"files_uploaded={len(result.files_uploaded)}\n")
            f.write(f"files_deleted={len(result.files_deleted)}\n")
            f.write(f"local_files_count={local_files_count}\n")