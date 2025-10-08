#include "./serverTCP.h"

void HandleClient(int sock) {
	char buffer[BUFFSIZE];
	int received = -1;

	if ((received = recv(sock, buffer, BUFFSIZE, 0)) < 0) {
		Die("Failed to receive initial bytes from client");
	}
	while (received > 0) {
		if (send(sock, buffer, received, 0) != received) {
			Die("Failed to send bytes to client");
		}
		if ((received = recv(sock, buffer, BUFFSIZE, 0)) < 0) {
			Die("Failed to receive additional bytes from client");
		}
	}
	close(sock);
}


int main(int argc, char *argv[]){
	int serversock, clientsock;
	struct sockaddr_in echoserver, echoclient;

	if (argc != 2) {
		fprintf(stderr, "USAGE: echoserver <port>\n");
		exit(1);
	}
	if ((serversock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
		Die("Failed to create socket");
	}
	memset(&echoserver, 0, sizeof(echoserver));
	echoserver.sin_family = AF_INET;
	echoserver.sin_addr.s_addr = htonl(INADDR_ANY);
	echoserver.sin_port = htons(atoi(argv[1]));

	if (bind(serversock, (struct sockaddr *) &echoserver, sizeof(echoserver)) < 0){
		Die("Failed to bind the server socket");
	}
	if (listen(serversock, MAXPENDING) < 0) {
		Die("Failed to listen on server socket");
	}

	while(1) {
		unsigned int clientlen = sizeof(echoclient);
		if ((clientsock = accept(serversock, (struct sockaddr *) &echoclient, &clientlen)) <0){
			Die("Failed to accept client connection");
		}
		fprintf(stdout, "Client connected : %s\n", inet_ntoa(echoclient.sin_addr));
		HandleClient(clientsock);
	}
}
