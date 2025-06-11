#!/bin/bash

set -e

DRACULNS_DIR="/usr/share/draculns"
BIN_PATH="/usr/local/bin/draculns"

echo "[*] Instalando DraculNS..."

# Verifica se está rodando como root
if [ "$EUID" -ne 0 ]; then
  echo " [*] Por favor execute como root (sudo)."
  exit 1
fi

# Cria diretório alvo
mkdir -p "$DRACULNS_DIR"

# Copia os arquivos para /usr/share/draculns
cp draculns.py "$DRACULNS_DIR/"
cp mac_vendors.json "$DRACULNS_DIR/"

# Dá permissão executável para o script Python
chmod +x "$DRACULNS_DIR/draculns.py"

# Cria script wrapper em /usr/local/bin
cat > "$BIN_PATH" << EOF
#!/bin/bash
if [ "\$EUID" -ne 0 ]; then
  echo " [!] Este script precisa ser executado com sudo ou como root."
  echo " [*] Tente: sudo draculns \$@"
  exit 1
fi
python3 $DRACULNS_DIR/draculns.py "\$@"
EOF

# Dá permissão executável para o wrapper
chmod +x "$BIN_PATH"

echo " [*] Instalação concluída!"
echo " [*] Você pode executar o DraculNS digitando: sudo draculns"
