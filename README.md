# DraculNS

![Descrição da imagem](exemplo.png)

## Descrição

O DraculNS é um script em Python3 desenvolvido por mim para realizar varreduras de portas em uma rede. Ele foi projetado para facilitar a identificação de dispositivos e serviços presentes na rede.

Este script utiliza técnicas de varredura TCP para identificar portas abertas nos dispositivos da rede. Além disso, o DraculNS também é capaz de obter informações sobre os serviços encontrados nas portas, incluindo suas versões. Essas informações podem ser úteis para entender melhor a configuração e o estado dos dispositivos na rede.

Com o DraculNS, você pode executar varreduras em uma ampla gama de endereços IP e interfaces de rede. Ele fornece uma saída clara e organizada, mostrando os serviços encontrados e suas respectivas versões. Isso pode ajudar na detecção de vulnerabilidades e na identificação de serviços desatualizados ou inseguros na rede.

**Autor:** Fábio Monteiro  
**GitHub:** [https://github.com/fabiosilvamonteiro/scripts_publicos](https://github.com/fabiosilvamonteiro/scripts_publicos)  
**LinkedIn:** [https://www.linkedin.com/in/fabio-silva-monteiro/](https://www.linkedin.com/in/fabio-silva-monteiro/)  

## Aviso Legal

Este script foi criado para fins educacionais e de teste. Qualquer uso indevido deste script, incluindo atividades ilegais, é estritamente proibido. Não me responsabilizo por qualquer uso indevido deste script. Utilize-o de maneira ética e responsável.

## Pré-requisitos

Para executar o DraculNS, você precisará:

1. Python 3 instalado em seu sistema.

```bash
apt-get install python3
```

2. Pacotes Python específicos. Estes podem ser instalados através do pip, o gerenciador de pacotes do Python. A lista de pacotes necessários inclui:

   * argparse
   * nmap
   * ipaddress
   * time
   * schedule
   * scapy
   * mac_vendor_lookup
   * rich


Para instalar todos esses pacotes, você pode utilizar o seguinte comando:

```bash
pip install argparse nmap ipaddress scapy mac_vendor_lookup rich time schedule
```

Caso você tenha alguma dificuldade, tente atualizar o pacote aiohttp

```bash
sudo pip3 install --upgrade aiohttp
```

## Como usar

Siga estas etapas para usar o DraculNS:

1. Baixe o script do meu repositório do GitHub ou clone-o em seu ambiente de trabalho local.

```bash
wget https://raw.githubusercontent.com/fabiosilvamonteiro/draculns/main/draculns.py
```

2. Altere as permissões do script para torná-lo executável. Você pode fazer isso com o comando `chmod`:

```bash
chmod +x draculns.py
```

3. Execute o script com privilégios de superusuário. Isso é necessário porque a varredura de rede precisa desses privilégios. Use o comando `sudo`:

```bash
sudo python3 draculns.py
```

Por padrão, o DraculNS realiza a varredura na rede '192.168.0.0/24' através da interface 'eth0'. Se você quiser especificar uma rede ou interface diferentes, pode usar as opções '-ip' e '-i':

```bash
sudo python3 draculns.py -ip 10.0.0.0/24 -i wlan0
```

Se quiser que a varredura seja realizada periodicamente (a cada 1 minuto), adicione a opção '-l':

```bash
sudo python3 draculns.py -l
```

## Contribuições

Ajude comprando nosso aplicativo de Google Hacking que disponibiliza dorks específicas para pentesting, mais informaçãoes em:

https://play.google.com/store/apps/details?id=com.gdraculdorksmobile&pli=1

Caso encontre problemas ou tenha sugestões de melhorias, sinta-se à vontade para abrir uma issue ou enviar um pull request no [repositório GitHub](https://github.com/fabiosilvamonteiro/scripts_publicos). Sua contribuição é muito bem-vinda! 

Para mais informações, visite meu perfil no [LinkedIn](https://www.linkedin.com/in/fabio-silva-monteiro/).
