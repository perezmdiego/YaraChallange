# Yara Challange

API que permite la integracion con YARA para el manejo de reglas con el fin de analizar archivos y textos en busca de patrones, informacion o malware.


## Tecnologias 📦
+ Python3
+ Flask
+ SQLAlchemy
+ MySQL
+ Docker

## Instalación 🔧

Se recomenda el uso de entornos virtuales(**virtualenv**) para la instalacion de las dependencias y la aplicacion.

``` bash
$ sudo apt install virtualenv python3 python3-pip git-core
$ virtualenv envName -p python3
$ source envName/bin/activate
$ git clone https://github.com/perezmdiego/YaraChallange.git
$ cd YaraChallange
$ pip install -r requirements.txt
```


## Ejecucion ⚙️

#### 1. MySQL Docker Container

``` bash
$ docker run -d -p 33060:3306 --name mysql-db -e MYSQL_ROOT_PASSWORD=secret mysql
```
#### 2. Python App

``` bash
$ python3 app.py
```
#### 3. On Terminal
``` bash
$ curl --request POST   --url http://localhost:5000/api/rule   --header 'content-type: application/json'   --data '{  "name":"esto no es coca papi rule",  "rule":"rule EstoNoEsCocaPapiRule\r\n{\r\n strings:\r\n $my_text_string = \"esto no es coca papi\"\r\n condition:\r\n   $my_text_string\r\n}"  }'
{
  "id": 1, 
  "name": "esto no es coca papi rule", 
  "rule": "rule EstoNoEsCocaPapiRule\r\n{\r\n strings:\r\n $my_text_string = \"esto no es coca papi\"\r\n condition:\r\n   $my_text_string\r\n}"
}

```

