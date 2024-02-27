# Secure File Backup System

## Course Information
This project is developed as part of the coursework for Defensive Systems Programming (20937), at The Open University of Israel. The goal is to implement a secure client-server system for file backup, utilizing encryption for secure file transfer.

## General Description
The Secure File Backup System is designed to facilitate the secure storage of files on a remote server. The system comprises two main components: a server implemented in Python and a client implemented in C++. This setup ensures robust security measures are in place for encrypting files before transmission and for secure communication between the client and server.

### System Workflow
- **Registration/Login:** Clients begin by either registering with the server or logging in if already registered.
- **Key Exchange:** The client and server exchange encryption keys to secure the communication channel.
  - The client generates a pair of RSA keys (public and private).
  - The public key is sent to the server.
  - The server generates an AES session key, encrypts it with the client's public key, and sends it back.
  - The client decrypts the session key using its private key.
- **File Encryption and Transfer:** The client encrypts files using the session key before sending them to the server, ensuring secure backup.
- **File Integrity:** A CRC32 checksum is used for verifying the integrity of the received file on the server side.

## Technical Details
- **Client:** Implemented in C++11, utilizing the Boost and CryptoPP libraries for networking and encryption functionalities.
- **Server:** Implemented in Python 3.9, using PyCryptoDome for encryption and SQLite for database management.
- **Concurrency:** The server is capable of handling multiple client connections simultaneously through threading.
- **Environment:** Developed and tested on Windows 11 using Visual Studio 2022.

## Build Instructions

### Client (C++)
1. **Boost Library:**
   - Download from [Boost official website](https://www.boost.org/).
   - Compile using `b2.exe` with the appropriate flags for your system.
2. **CryptoPP Library:**
   - Download from [CryptoPP official website](https://cryptopp.com/).
   - Compile the `cryptlib` project for your target architecture.
3. **Project Configuration:**
   - Adjust include directories and library dependencies in your project settings to include Boost and CryptoPP paths.

### Server (Python)
- Install dependencies: `pip install pycryptodome`

## Running the System

### Client
- Build `client` project and execute `main.cpp` make sure `transfer.info` and `me.info` (optional - only needed after registeration) files in the same directory. These files contain backup information, credentials, and private key data.

### Server
- Execute `main.py` in your python IDE.

## Additional Resources
- Detailed project requirements, protocol descriptions, and other relevant materials are available in `mmn15-2023c.pdf`.

## Acknowledgements
This project was developed by Guy Perry as part of the Defensive Systems Programming (20937) at The Open University of Israel.
