#include "check.hpp"
#include "common.h"

#include <iostream>
#include <cstdlib>
#include <cstring>
#include <string>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int main(int argc, char *argv[]) {
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <server_ip> <port>" << std::endl;
        return EXIT_FAILURE;
    }

    const char *server_ip = argv[1];
    int port = std::atoi(argv[2]);
    if (port <= 0 || port > 65535) {
        std::cerr << "Invalid port: " << argv[2] << std::endl;
        return EXIT_FAILURE;
    }

    // Create socket
    int sock_fd = check(make_socket(SOCK_STREAM));

    // Prepare server address
    sockaddr_in server_addr = {};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(static_cast<unsigned short>(port));
    int res = inet_pton(AF_INET, server_ip, &server_addr.sin_addr);
    if (res <= 0) {
        std::cerr << "Invalid IP address: " << server_ip << std::endl;
        return EXIT_FAILURE;
    }

    // Connect to server
    check(connect(sock_fd, (sockaddr*)&server_addr, sizeof(server_addr)));
    std::cout << "Connected to " << server_ip << ":" << port << std::endl;

    std::string line;
    char buf[128];
    while (true) {
        // Prompt user
        std::cout << "Enter your guess (1-100): ";
        if (!std::getline(std::cin, line)) {
            std::cerr << "Input error or EOF" << std::endl;
            break;
        }
        if (line.empty()) continue;

        // Send guess to server
        std::string msg = line + "\n";
        check(send(sock_fd, msg.c_str(), msg.size(), 0));

        // Receive response
        ssize_t received = check(recv(sock_fd, buf, sizeof(buf) - 1, 0));
        if (received == 0) {
            std::cerr << "Server closed connection" << std::endl;
            break;
        }
        buf[received] = '\0';
        std::string response(buf);
        response.erase(response.find_last_not_of("\r\n") + 1);

        // Display server response
        if (response == ">") {
            std::cout << "Too low!" << std::endl;
        } else if (response == "<") {
            std::cout << "Too high!" << std::endl;
        } else if (response == "=") {
            std::cout << "Correct! You guessed the number." << std::endl;
            break;
        } else {
            std::cout << "Unknown response: " << response << std::endl;
        }
    }

    close(sock_fd);
    return EXIT_SUCCESS;
}
