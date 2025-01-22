#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <process.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "libssl.lib")
#pragma comment(lib, "libcrypto.lib")

// Définition des constantes
#define PORT 5000
#define MAX_CLIENTS 100
#define BUFFER_SIZE 1024

// Structure représentant un client
typedef struct {
    SSL *ssl;
    char username[50];
} Client;

// Variables globales
Client *clients[MAX_CLIENTS];
CRITICAL_SECTION clients_mutex;

// Initialisation du contexte SSL
SSL_CTX *initialize_ssl() {
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();

    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        fprintf(stderr, "Impossible de créer le contexte SSL\n");
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_certificate_file(ctx, "server.crt", SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(ctx, "server.key", SSL_FILETYPE_PEM) <= 0) {
        fprintf(stderr, "Erreur lors du chargement des certificats SSL\n");
        exit(EXIT_FAILURE);
    }

    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "La clé privée ne correspond pas au certificat public\n");
        exit(EXIT_FAILURE);
    }

    return ctx;
}

// Nettoyage des ressources SSL
void cleanup_ssl(SSL_CTX *ctx) {
    if (ctx) SSL_CTX_free(ctx);
    EVP_cleanup();
}

// Fonction de journalisation
void log_event(const char *event) {
    FILE *log_file = fopen("server.log", "a");
    if (log_file != NULL) {
        fprintf(log_file, "%s\n", event);
        fclose(log_file);
    }
}

// Fonction pour diffuser un message à tous les clients sauf l'expéditeur
void broadcast_message(char *message, Client *sender) {
    EnterCriticalSection(&clients_mutex);
    for (int i = 0; i < MAX_CLIENTS; ++i) {
        if (clients[i] != NULL && clients[i] != sender) {
            char formatted_message[BUFFER_SIZE + 50];
            snprintf(formatted_message, sizeof(formatted_message), "%s : %s", sender->username, message);

            if (SSL_write(clients[i]->ssl, formatted_message, (int)strlen(formatted_message)) <= 0) {
                fprintf(stderr, "Erreur lors de l'envoi du message\n");
            }
        }
    }
    LeaveCriticalSection(&clients_mutex);
}

void send_to_self(char *message, Client *sender) {
    char formatted_message[BUFFER_SIZE + 50];
    snprintf(formatted_message, sizeof(formatted_message), "Moi : %s", message);

    if (SSL_write(sender->ssl, formatted_message, (int)strlen(formatted_message)) <= 0) {
        fprintf(stderr, "Erreur lors de l'envoi du message à soi-même\n");
    }
}

// Fonction pour retirer un client de la liste
void remove_client(Client *client) {
    EnterCriticalSection(&clients_mutex);
    for (int i = 0; i < MAX_CLIENTS; ++i) {
        if (clients[i] == client) {
            clients[i] = NULL;
            break;
        }
    }
    LeaveCriticalSection(&clients_mutex);

    SSL_free(client->ssl);
    free(client);
}

// Fonction pour gérer un client (thread)
unsigned __stdcall handle_client(void *arg) {
    char buffer[BUFFER_SIZE];
    char message[BUFFER_SIZE];
    Client *client = (Client *)arg;

    snprintf(message, sizeof(message), "%s a rejoint la discussion.", client->username);
    printf("%s\n", message);
    log_event(message);
    broadcast_message(message, client);

    SSL_write(client->ssl, "Bienvenue sur le serveur sécurisé de chat !", 41);

    while (1) {
        int recv_size = SSL_read(client->ssl, buffer, BUFFER_SIZE);
        if (recv_size > 0) {
            buffer[recv_size] = '\0';

            if (strcmp(buffer, "/quit") == 0) {
                snprintf(message, sizeof(message), "%s a quitté la discussion.", client->username);
                printf("%s\n", message);
                log_event(message);
                broadcast_message(message, client);
                SSL_shutdown(client->ssl);
                remove_client(client);
                break;
            }

            send_to_self(buffer, client);
            broadcast_message(buffer, client);
        } else if (recv_size == 0) {
            snprintf(message, sizeof(message), "%s a quitté la discussion.", client->username);
            printf("%s\n", message);
            log_event(message);
            broadcast_message(message, client);
            SSL_shutdown(client->ssl);
            remove_client(client);
            break;
        }
    }
    return 0;
}

// Fonction pour ajouter un client à la liste
int add_client(Client *client) {
    EnterCriticalSection(&clients_mutex);
    for (int i = 0; i < MAX_CLIENTS; ++i) {
        if (clients[i] == NULL) {
            clients[i] = client;
            LeaveCriticalSection(&clients_mutex);
            return 0;
        }
    }
    LeaveCriticalSection(&clients_mutex);
    return -1;
}

// Gestionnaire de signal pour Windows
BOOL WINAPI CtrlHandler(DWORD fdwCtrlType) {
    switch (fdwCtrlType) {
        case CTRL_C_EVENT:
        case CTRL_CLOSE_EVENT:
            printf("\nFermeture du serveur...\n");
            cleanup_ssl(NULL);
            exit(0);
            return TRUE;
        default:
            return FALSE;
    }
}

int main() {
    WSADATA wsaData;
    SOCKET server_socket = INVALID_SOCKET, client_socket = INVALID_SOCKET;
    struct sockaddr_in server_addr, client_addr;
    int addr_len = sizeof(client_addr);
    HANDLE thread_handle;

    // Initialisation de Winsock
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        fprintf(stderr, "WSAStartup failed\n");
        return 1;
    }

    // Initialisation de la section critique
    InitializeCriticalSection(&clients_mutex);

    SSL_CTX *ctx = initialize_ssl();

    // Création du socket serveur
    if ((server_socket = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET) {
        fprintf(stderr, "Échec de la création du socket\n");
        WSACleanup();
        return 1;
    }

    // Configuration de l'adresse du serveur
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    // Liaison du socket
    if (bind(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
        fprintf(stderr, "Erreur lors du bind\n");
        closesocket(server_socket);
        WSACleanup();
        return 1;
    }

    // Mise en écoute
    if (listen(server_socket, 10) == SOCKET_ERROR) {
        fprintf(stderr, "Erreur lors du listen\n");
        closesocket(server_socket);
        WSACleanup();
        return 1;
    }

    // Configuration du gestionnaire de signal
    if (!SetConsoleCtrlHandler(CtrlHandler, TRUE)) {
        fprintf(stderr, "Impossible d'installer le gestionnaire de signal\n");
        return 1;
    }

    printf("Serveur en attente de connexions sur le port %d...\n", PORT);

    while (1) {
        if ((client_socket = accept(server_socket, (struct sockaddr *)&client_addr, &addr_len)) == INVALID_SOCKET) {
            fprintf(stderr, "Erreur lors de l'accept\n");
            continue;
        }

        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, (int)client_socket);
        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
            closesocket(client_socket);
            SSL_free(ssl);
            continue;
        }

        Client *client = (Client *)malloc(sizeof(Client));
        if (client == NULL) {
            fprintf(stderr, "Erreur d'allocation mémoire pour le client\n");
            closesocket(client_socket);
            SSL_free(ssl);
            continue;
        }
        client->ssl = ssl;

        SSL_read(ssl, client->username, 50);
        client->username[49] = '\0';

        if (strlen(client->username) == 0) {
            printf("Connexion refusée : nom d'utilisateur vide\n");
            SSL_shutdown(ssl);
            SSL_free(ssl);
            closesocket(client_socket);
            free(client);
            continue;
        }

        printf("%s s'est connecté.\n", client->username);
        log_event(client->username);

        if (add_client(client) < 0) {
            printf("Serveur plein, connexion refusée pour %s\n", client->username);
            SSL_shutdown(ssl);
            SSL_free(ssl);
            closesocket(client_socket);
            free(client);
            continue;
        }

        thread_handle = (HANDLE)_beginthreadex(NULL, 0, handle_client, (void *)client, 0, NULL);
        CloseHandle(thread_handle);
    }

    closesocket(server_socket);
    DeleteCriticalSection(&clients_mutex);
    cleanup_ssl(ctx);
    WSACleanup();
    return 0;
}