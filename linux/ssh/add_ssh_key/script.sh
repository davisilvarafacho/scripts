#!/bin/bash

# Script para adicionar chave SSH em servidor remoto
# Uso: ./add_ssh_key.sh [usuario@servidor] [caminho_chave_publica]

set -e  # Sai se houver erro

# Cores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Função para exibir mensagens coloridas
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[AVISO]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERRO]${NC} $1"
}

# Função de ajuda
show_help() {
    echo "Uso: $0 [usuario@servidor] [caminho_chave_publica]"
    echo ""
    echo "Parâmetros:"
    echo "  usuario@servidor      - Usuário e endereço do servidor (ex: user@192.168.1.100)"
    echo "  caminho_chave_publica - Caminho para a chave pública (opcional, padrão: ~/.ssh/id_rsa.pub)"
    echo ""
    echo "Exemplos:"
    echo "  $0 root@192.168.1.100"
    echo "  $0 user@example.com ~/.ssh/id_ed25519.pub"
    echo ""
    echo "Opções:"
    echo "  -h, --help           - Mostra esta ajuda"
    echo "  -g, --generate       - Gera uma nova chave SSH antes de enviar"
    echo "  -p, --port PORT      - Especifica a porta SSH (padrão: 22)"
}

# Função para gerar nova chave SSH
generate_ssh_key() {
    local key_type="ed25519"
    local key_file="$HOME/.ssh/id_$key_type"
    
    if [ -f "$key_file" ]; then
        print_warning "Chave SSH já existe em $key_file"
        read -p "Deseja sobrescrever? (s/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Ss]$ ]]; then
            print_status "Usando chave existente"
            return 0
        fi
    fi
    
    print_status "Gerando nova chave SSH..."
    read -p "Digite seu email: " email
    
    ssh-keygen -t "$key_type" -C "$email" -f "$key_file"
    
    if [ $? -eq 0 ]; then
        print_status "Chave SSH gerada com sucesso!"
        PUBLIC_KEY="$key_file.pub"
    else
        print_error "Falha ao gerar chave SSH"
        exit 1
    fi
}

# Função para verificar se a chave já existe no servidor
check_existing_key() {
    local remote_host="$1"
    local port="$2"
    local key_content="$3"
    
    print_status "Verificando se a chave já existe no servidor..."
    
    # Extrai apenas a parte da chave (sem o comentário)
    local key_fingerprint=$(echo "$key_content" | awk '{print $2}')
    
    if ssh -p "$port" "$remote_host" "grep -q '$key_fingerprint' ~/.ssh/authorized_keys 2>/dev/null"; then
        print_warning "Esta chave já está presente no servidor"
        return 0
    else
        return 1
    fi
}

# Função principal para adicionar chave SSH
add_ssh_key() {
    local remote_host="$1"
    local public_key_file="$2"
    local port="$3"
    
    # Verifica se a chave pública existe
    if [ ! -f "$public_key_file" ]; then
        print_error "Arquivo de chave pública não encontrado: $public_key_file"
        exit 1
    fi
    
    # Lê o conteúdo da chave pública
    local key_content=$(cat "$public_key_file")
    
    # Verifica se a chave já existe
    if check_existing_key "$remote_host" "$port" "$key_content"; then
        read -p "Deseja continuar mesmo assim? (s/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Ss]$ ]]; then
            print_status "Operação cancelada"
            exit 0
        fi
    fi
    
    print_status "Adicionando chave SSH ao servidor $remote_host..."
    
    # Cria o diretório .ssh se não existir e adiciona a chave
    ssh -p "$port" "$remote_host" "
        mkdir -p ~/.ssh
        chmod 700 ~/.ssh
        echo '$key_content' >> ~/.ssh/authorized_keys
        chmod 600 ~/.ssh/authorized_keys
        sort ~/.ssh/authorized_keys | uniq > ~/.ssh/authorized_keys.tmp
        mv ~/.ssh/authorized_keys.tmp ~/.ssh/authorized_keys
    "
    
    if [ $? -eq 0 ]; then
        print_status "Chave SSH adicionada com sucesso!"
        print_status "Testando conexão..."
        
        # Testa a conexão
        if ssh -p "$port" -o BatchMode=yes -o ConnectTimeout=5 "$remote_host" "echo 'Conexão SSH funcionando!'" 2>/dev/null; then
            print_status "Teste de conexão bem-sucedido!"
        else
            print_warning "Chave adicionada, mas teste de conexão falhou"
        fi
    else
        print_error "Falha ao adicionar chave SSH"
        exit 1
    fi
}

# Variáveis padrão
GENERATE_KEY=false
SSH_PORT=22
PUBLIC_KEY="$HOME/.ssh/id_rsa.pub"

# Processa argumentos
while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            show_help
            exit 0
            ;;
        -g|--generate)
            GENERATE_KEY=true
            shift
            ;;
        -p|--port)
            SSH_PORT="$2"
            shift 2
            ;;
        *)
            if [ -z "$REMOTE_HOST" ]; then
                REMOTE_HOST="$1"
            elif [ -z "$CUSTOM_PUBLIC_KEY" ]; then
                CUSTOM_PUBLIC_KEY="$1"
            else
                print_error "Argumento inválido: $1"
                show_help
                exit 1
            fi
            shift
            ;;
    esac
done

# Verifica se o host remoto foi fornecido
if [ -z "$REMOTE_HOST" ]; then
    print_error "Você deve especificar o servidor remoto"
    show_help
    exit 1
fi

# Usa chave personalizada se fornecida
if [ -n "$CUSTOM_PUBLIC_KEY" ]; then
    PUBLIC_KEY="$CUSTOM_PUBLIC_KEY"
fi

# Gera nova chave se solicitado
if [ "$GENERATE_KEY" = true ]; then
    generate_ssh_key
fi

# Verifica se ssh-copy-id está disponível (método mais simples)
if command -v ssh-copy-id &> /dev/null; then
    print_status "Usando ssh-copy-id para adicionar a chave..."
    ssh-copy-id -i "$PUBLIC_KEY" -p "$SSH_PORT" "$REMOTE_HOST"
    
    if [ $? -eq 0 ]; then
        print_status "Chave SSH adicionada com sucesso usando ssh-copy-id!"
        exit 0
    else
        print_warning "ssh-copy-id falhou, tentando método manual..."
    fi
fi

# Método manual
print_status "Usando método manual para adicionar a chave..."
add_ssh_key "$REMOTE_HOST" "$PUBLIC_KEY" "$SSH_PORT"

print_status "Processo concluído!"
print_status "Você agora pode se conectar usando: ssh -p $SSH_PORT $REMOTE_HOST"
