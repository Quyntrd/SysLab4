#include "check.hpp"
#include "common.h"

#include <iostream>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <chrono>
#include <iomanip>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <signal.h>

// Atomic log write: writes a single line ending with '\n'
void log_atomic(const std::string &msg) {
    // Prepare timestamp
    std::time_t t = std::time(nullptr);
    struct tm tm_buf;
    localtime_r(&t, &tm_buf);
    char timebuf[20]; // YYYY-MM-DD HH:MM:SS
    std::strftime(timebuf, sizeof(timebuf), "%F %T", &tm_buf);

    // Construct full line with timestamp
    std::string line = "[" + std::string(timebuf) + "] " + msg + '\n';
    write(STDOUT_FILENO, line.c_str(), line.size());
}

// SIGCHLD handler: reap all dead children
void sigchld_handler(int) {
    while (true) {
        pid_t pid = waitpid(-1, nullptr, WNOHANG);
        if (pid <= 0) break;
    }
}

void handle_client(int client_fd, sockaddr_in client_addr) {
    char client_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));
    int client_port = ntohs(client_addr.sin_port);

    // Log connection with clearer message
    log_atomic(std::string(client_ip) + ":" + std::to_string(client_port) + " - connected");

    // Seed random with time and pid
    std::srand(static_cast<unsigned int>(std::time(nullptr)) ^ getpid());
    int secret = 1 + std::rand() % 100;
    log_atomic(std::string(client_ip) + ":" + std::to_string(client_port) + " - secret number generated");

    char buf[128];
    while (true) {
        // Receive client's guess
        ssize_t received = check(recv(client_fd, buf, sizeof(buf) - 1, 0));
        buf[received] = '\0';
        std::string guess_str(buf);
        guess_str.erase(guess_str.find_last_not_of("\r\n") + 1);

        // Log received guess
        log_atomic(std::string(client_ip) + ":" + std::to_string(client_port) + " - received guess '" + guess_str + "'");

        // Compare and prepare response
        int guess = std::atoi(guess_str.c_str());
        const char *response;
        if (guess < secret) {
            response = ">";
            log_atomic(std::string(client_ip) + ":" + std::to_string(client_port) + " - responding '>' (too low)");
        } else if (guess > secret) {
            response = "<";
            log_atomic(std::string(client_ip) + ":" + std::to_string(client_port) + " - responding '<' (too high)");
        } else {
            response = "=";
            log_atomic(std::string(client_ip) + ":" + std::to_string(client_port) + " - responding '=' (correct)");
        }

        // Send response
        check(send(client_fd, response, std::strlen(response), 0));

        if (response[0] == '=') {
            break;
        }
    }

    // Log disconnection
    log_atomic(std::string(client_ip) + ":" + std::to_string(client_port) + " - disconnected");
    close(client_fd);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <port>" << std::endl;
        return EXIT_FAILURE;
    }

    // Parse port
    int port = std::atoi(argv[1]);
    if (port <= 0 || port > 65535) {
        std::cerr << "Invalid port: " << argv[1] << std::endl;
        return EXIT_FAILURE;
    }

    // Install SIGCHLD handler
    struct sigaction sa{};
    sa.sa_handler = sigchld_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART | SA_NOCLDSTOP;
    check(sigaction(SIGCHLD, &sa, nullptr));

    // Create listening socket
    int listen_fd = check(make_socket(SOCK_STREAM));
    // Allow reuse of address
    int opt = 1;
    check(setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)));

    // Bind and listen
    sockaddr_in addr = local_addr(static_cast<unsigned short>(port));
    check(bind(listen_fd, (sockaddr*)&addr, sizeof(sockaddr_in)));
    check(listen(listen_fd, SOMAXCONN));

    std::cout << "[INFO] Server listening on port " << port << std::endl;

    // Main accept loop
    while (true) {
        sockaddr_in client_addr;
        socklen_t addrlen = sizeof(client_addr);
        int client_fd = check(accept(listen_fd, (sockaddr*)&client_addr, &addrlen));

        pid_t pid = check(fork());
        if (pid == 0) {
            // Child process handles client
            close(listen_fd);
            handle_client(client_fd, client_addr);
            _exit(EXIT_SUCCESS);
        } else {
            // Parent closes client socket and continues
            close(client_fd);
        }
    }

    // Never reached
    close(listen_fd);
    return EXIT_SUCCESS;
}
