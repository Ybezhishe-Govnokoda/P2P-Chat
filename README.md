# Encrypted P2P Chat (C Version)

Простой зашифрованный **peer-to-peer чат**, написанный на чистом **C**. 

---

## Возможности

✅ Поддержка **нескольких клиентов** (до 50 одновременно)  
✅ Каждый клиент обрабатывается в **отдельном потоке**  
✅ Чистая реализация на **C**  
✅ Базовая передача сообщений между клиентом и сервером  

---

## Технологии

| Компонент | Используется |
|------------|---------------|
| **Язык** | C |
| **Библиотеки** | Winsock2, OpenSSL |
| **ОС** | Cross-platform |
| **Компилятор** | MSVC/gcc |

---

## Установка и запуск

### 1. Скомпилировать сервер
**Windows:**

```bash
cl server.c /I "C:\OpenSSL-Win64\include" /link /LIBPATH:"C:\OpenSSL-Win64\lib\VC\x64\MD" libssl.lib libcrypto.lib ws2_32.lib
```
Если у вас другой путь к папке с OpenSSL - укажите его. 
В /LIBPATH: нужно указать полный путь к файлам libssl.lib и libcrypto.lib

**Linux/Mac:**

```bash
gcc server.c msg_encryption.c -o server \
    -lssl -lcrypto -pthread
```


### 2. Скомпилировать клиент
**Windows:**

```bash
cl client.c /I "C:\OpenSSL-Win64\include" /link /LIBPATH:"C:\OpenSSL-Win64\lib\VC\x64\MD" libcrypto.lib ws2_32.lib
```

**Linux/Mac:**

```bash
gcc client.c msg_encryption.c -o client \
    -lssl -lcrypto -pthread
```

### 3. Запуск
Сначала нужно запустить сервер:
```bash
server.exe
```
Затем клиент:
```bash
client.exe <вставить сюда ip-адрес>
```

**Linux/Mac:**
```bash
./server
```
```bash
./client <ip>
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