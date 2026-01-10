# Encrypted P2P Chat (C Version)

Simple encrypted **peer-to-peer chat**, written in pure **C**.

---

## Возможности

✅ Support **several clients** (up to 50 simultaneously)  
✅ Each client is handled in a **separate thread**  
✅ Clean implementation in **C**  
✅ Basic message transmission between client and server  

---

## Технологии

| Component | Used |
|------------|---------------|
| **Language** | C |
| **Libraries** | Winsock2, OpenSSL |
| **OS** | Cross-platform |
| **Compiler** | MSVC/gcc |

---

## Запуск

After build need to run server:
```bash
server.exe
```
Then client:
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

To exit server, type "exit"
```bash
exit
```

To change nickname, type [NAME] + new name
```bash
[NAME]User
```