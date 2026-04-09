RFTP - Reliable File Transfer Protocol



Overview:

RFTP is a custom-built secure file transfer protocol implemented in Python.  

It enables reliable and encrypted communication between a client and server using a custom protocol design.





Features:

\-  Reliable file transfer with retransmission support  

\-  AES-256-CBC encryption  

\-  Client-server architecture  

\-  Custom protocol implementation  

\-  Data integrity and secure communication  



\---



Tech Stack

\- Python 3

\- Socket Programming

\- PyCryptodome (AES Encryption)



\---



Project Structure

│── client.py # Client-side logic

│── server.py # Server-side logic

│── protocol.py # Custom protocol handling

│── crypto\_utils.py # Encryption/Decryption

│── server\_files/ # Files stored on server

│── client\_files/ # Files received by client



&#x20;Installation



1\. Clone the repository

git clone https://github.com/rohithkarning-debug/rftp\_project.git



cd rftp\_project



2\. Install dependencies

pip install pycryptodome



How to Run



&#x20;Step 1: Start the Server-python server.py

&#x20;Step 2: Start the Client (in another device or terminal)-python client.py







How it Works

1\. Client connects to server using sockets  

2\. Custom protocol establishes communication  

3\. Data is encrypted using AES-256-CBC  

4\. Files are transferred reliably with error handling  







&#x20;Notes

\- Make sure server runs before client  

\- Update IP/port if needed in code  

\- Ensure both client and server are on same network  





&#x20;Authors:

Rohith Karning

Rotela Haritej

Rhea Menon







