# ssh-register-new-key

## Usage

```bash
# Tornar o script executável
chmod +x add_ssh_key.sh

# Uso básico
./add_ssh_key.sh root@192.168.247.101

# Com chave personalizada
./add_ssh_key.sh root@192.168.247.101 ~/.ssh/id_ed25519.pub

# Gerando nova chave e adicionando
./add_ssh_key.sh -g root@192.168.247.101

# Com porta personalizada
./add_ssh_key.sh -p 2222 root@192.168.247.101
```
