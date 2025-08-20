import os
import sys
import django
from pathlib import Path
import mammoth

# 1. Descobre o caminho base do projeto (pasta onde está manage.py)
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.append(str(BASE_DIR))

# 2. Configura o Django
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "cifra.settings")
django.setup()

# 3. Agora que o Django está configurado, podemos importar os modelos
from core.models import Module, Lesson  # ajustado para casar com template

# 4. Caminho para os DOCX
DOCS_PATH = BASE_DIR / "scripts" / "cifra módulos"

# 5. Lista os arquivos encontrados
docx_files = list(DOCS_PATH.glob("*.docx"))
print(f"Arquivos encontrados: {[f.name for f in docx_files]}")

if not docx_files:
    print("Nenhum arquivo .docx encontrado. Verifique o caminho!")
    sys.exit(1)

# 6. Importa arquivos .docx
for file_path in docx_files:
    with open(file_path, "rb") as docx_file:
        result = mammoth.convert_to_html(docx_file)
        html_content = result.value

    # Testa se o conteúdo foi lido
    if not html_content.strip():
        print(f"⚠️  O arquivo {file_path.name} não gerou conteúdo HTML.")
        continue  # pula para o próximo arquivo

    # Nome do módulo = nome do arquivo sem extensão
    module_title = file_path.stem

    # Cria módulo (ou pega se já existir)
    module, created = Module.objects.get_or_create(
        title=module_title,
        defaults={'slug': module_title.lower().replace(" ", "-")}
    )
    if created:
        print(f"✅ Módulo criado: {module_title}")
    else:
        print(f"ℹ️  Módulo já existe: {module_title}")

    # Cria lição dentro do módulo
    lesson = Lesson.objects.create(
        module=module,
        title=f"Lição principal: {module_title}",
        slug=f"{module.slug}-main",
        content_html=html_content
    )
    print(f"   Lição criada: {lesson.title} (id={lesson.pk})")

print("Importação concluída!")