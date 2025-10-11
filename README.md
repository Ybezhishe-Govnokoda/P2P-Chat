# 🔐 Encrypted P2P Chat (C Version)

Простой зашифрованный **peer-to-peer чат**, написанный на чистом **C** с использованием **Winsock2**. 

---

## 🚀 Возможности

✅ Поддержка **нескольких клиентов** (до 50 одновременно)  
✅ Каждый клиент обрабатывается в **отдельном потоке**  
✅ Чистая реализация на **C**  
✅ Базовая передача сообщений между клиентом и сервером  

---

## 🧱 Технологии

| Компонент | Используется |
|------------|---------------|
| **Язык** | C |
| **Библиотеки** | Winsock2, OpenSSL |
| **ОС** | Windows |
| **Компилятор** | MSVC (Visual Studio) |

---

## ⚙️ Установка и запуск

### 1. Сгенерировать ключи
```bash
openssl genrsa -out server_priv.pem 2048
openssl rsa -in server_priv.pem -pubout -out server_pub.pem
```

### 2. Скомпилировать сервер
```bash
cl server.c /I "C:\OpenSSL-Win64\include" /link /LIBPATH:"C:\OpenSSL-Win64\lib\VC\x64\MD" libssl.lib libcrypto.lib ws2_32.lib
```
Если у вас другой путь к папке с OpenSSL - укажите его. 
В /LIBPATH: нужно указать полный путь к файлам libssl.lib и libcrypto.lib

### 3. Скомпилировать клиент
```bash
cl client.c /I "C:\OpenSSL-Win64\include" /link /LIBPATH:"C:\OpenSSL-Win64\lib\VC\x64\MD" libcrypto.lib ws2_32.lib
```

### 4. Запуск
Сначала нужно запустить сервер:
```bash
server.exe
```
Затем клиент:
```bash
client.exe <вставить сюда ip-адрес>
```

---

## Команды для сервера

Чтобы выйти с сервера, в поле для сообщений нужно ввести команду "exit"
```bash
exit
```

Чтобы сменить никнейм, нужно ввести [NAME] + новый ник
```bash
[NAME]Test
```