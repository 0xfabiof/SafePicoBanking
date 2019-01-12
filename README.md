# SafePicoBanking
A Java implementation of a Secure Channel in Socket Programming in the context of a simple ebanking prototype.

Full report in Portuguese available [here](https://web.fe.up.pt/~up201505331/projects/AC_picobanking_relatorio_FabioFreitas.pdf)

# Secure Channel

* Diffie-Hellman Key Agreement with Signature from the Server 

* Client verifies the signature using a X509 encoded Certificate

* Computation of a Shared Key

* Usage of AES CBC Mode to ensure communication confidentiality

* Usage of HMAC256 to ensure integrity and autentication of communications

# Usage

Compile lines:

> Server (compile): 
 
>   javac -cp commons-codec-1.7.jar server.java 
 
> Client (compile): 
 
>   javac -cp commons-codec-1.7.jar client.java 

Run lines:

> Server (execute): 
 
>   java -cp :commons-codec-1.7.jar server 
 
> Client (execute): 
 
>   java -cp :commons-codec-1.7.jar client 
