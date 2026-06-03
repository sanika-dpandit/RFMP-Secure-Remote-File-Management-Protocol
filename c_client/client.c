#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define HOST "127.0.0.1" // defining server IP address (localhost)
#define PORT 5000 // defining the server's port number

int main(int argc, char const* argv[]){
    int s; // file descriptor for the socket
    struct sockaddr_in server_addr; // struct to define the server address
    const char* start_packet = "SS,RFMP,v1.0,0"; // initial message sent to the server
    const char* command_input = "CM, openRead, example.txt"; // message to be sent

    s = socket(AF_INET, SOCK_STREAM, 0); // creating socket using ipv4 and tcp

    if (s<0){ // error handling for socket creation
        printf("Error in creating a socket.");
        return -1;
    }

    // configuring the server address structure
    server_addr.sin_family = AF_INET; //Address: IPv4
    server_addr.sin_port = htons(PORT); //Converting the port number to network byte order
    server_addr.sin_addr.s_addr = inet_addr(HOST); //Converting the IP address to network format

    // server connection
    if (connect(s, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("Connection failed."); // Printing a detailed error message
        close(s); //Closing the socket
        return -1;
    }

    printf("Successful connection to server."); // confirmation message

    // start packet to server
    send(s, start_packet, strlen(start_packet),0);
    printf("Sent start packet: %s\n", start_packet);

    // cmd input to server
    send(s, command_input, strlen(command_input), 0);
    printf("Sent start packet: %s\n", start_packet);

    close(s); // socket closing
    printf("Connection killed.\n");

    return 0; // successful execution
}
