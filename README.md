# 🖥️ Windows Server Event Viewer Portal

Portal interativo de análise de logs do Windows Server com detecção
automática de incidentes, troubleshooting assistido e base de conhecimento.

## Instalação

```bash
# 1. Clone ou copie os arquivos
cd windows_log_portal

# 2. Crie um ambiente virtual (recomendado)
python -m venv venv
venv\Scripts\activate        # Windows
source venv/bin/activate     # Linux/Mac

# 3. Instale as dependências
pip install -r requirements.txt

# 4. Execute o portal
streamlit run app.py
