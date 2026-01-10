# Encrypted P2P Chat (C Version)

Simple encrypted **peer-to-peer chat**, written in pure **C**.

---

## Abilities

✅ Support **several clients** (up to 50 simultaneously)  
✅ Each client is handled in a **separate thread**  
✅ Clean implementation in **C**  
✅ Basic message transmission between client and server  

---

## Technologies

| Component | Used |
|------------|---------------|
| **Language** | C |
| **Libraries** | Winsock2, OpenSSL |
| **OS** | Cross-platform |
| **Compiler** | MSVC/gcc |

---

## Launching

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

## Commands for client

To exit server, type "exit"
```bash
exit
```

To change nickname, type [NAME] + new name
```bash
[NAME]User
```