# DraculNS

![Descrição da imagem](exemplo.png)

## Descrição

O DraculNS é um script em Python3 desenvolvido por mim que realiza varreduras TCP utilizando o Nmap para identificar portas abertas nos dispositivos conectados à rede. Além de detectar as portas, o script coleta informações detalhadas sobre os serviços em execução, incluindo suas versões, oferecendo uma visão aprofundada da configuração e do estado dos dispositivos.

Um dos diferenciais do DraculNS é a capacidade de identificar dispositivos móveis, como celulares e tablets. Para isso, ele utiliza uma base de fabricantes conhecidos e analisa o fornecedor associado aos endereços MAC para inferir a natureza móvel do dispositivo. Além disso, a ferramenta destaca portas relevantes para segurança e exploração, como a porta 22, frequentemente associada a dispositivos iOS, e a porta 5555, comumente aberta em dispositivos Android com o modo desenvolvedor ativado.

## Requisitos

Para executar o DraculNS, você precisará:

1. Python 3 instalado em seu sistema.

```bash
sudo apt-get install python3
```

2. Pacotes Python específicos. Estes podem ser instalados através do pip, o gerenciador de pacotes do Python. A lista de pacotes necessários inclui:

* scapy
* python-nmap
* mac-vendor-lookup
* rich
* netifaces

Para instalar todos esses pacotes, você pode utilizar o seguinte comando:

```bash
sudo pip install scapy python-nmap mac-vendor-lookup rich netifaces --break-system-packages
```

## Como usar

Siga estas etapas para usar o DraculNS:

1. Baixe o script do meu repositório do GitHub ou clone-o em seu ambiente de trabalho local.

```bash
wget https://github.com/fabiosilvamonteiro/draculns.git)](https://github.com/fabiosilvamonteiro/draculns.git
```

2. Altere as permissões do script para torná-lo executável. Você pode fazer isso com o comando `chmod`:

```bash
sudo chmod +x install.sh
```

3. Execute o script com privilégios de superusuário. Isso é necessário porque a varredura de rede precisa desses privilégios. Use o comando `sudo`:

```bash
sudo bash install.sh
```

Por padrão, o DraculNS realiza a varredura na rede '192.168.0.0/24' através da interface 'eth0'. Se você quiser especificar uma rede ou interface diferentes, pode usar as opções '-ip' e '-i':

```bash
sudo draculns -ip 10.0.2.0/24 -i wlan0
```

Se quiser que a varredura seja realizada periodicamente (a cada 30 segundos), adicione a opção '-l':

```bash
sudo draculns -l
```

## Aviso Legal

Este script foi criado para fins educacionais e de teste. Qualquer uso indevido deste script, incluindo atividades ilegais, é estritamente proibido. Não me responsabilizo por qualquer uso indevido deste script. Utilize-o de maneira ética e responsável.
