#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <pthread.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <signal.h>

// Définition des constantes
#define PORT 5000            // Port d'écoute du serveur
#define MAX_CLIENTS 100      // Nombre maximum de clients supportés simultanément
#define BUFFER_SIZE 1024     // Taille du buffer pour les messages

// Initialisation du contexte SSL
SSL_CTX *initialize_ssl() {
    SSL_library_init();                      // Initialisation des bibliothèques SSL
    SSL_load_error_strings();                // Chargement des messages d'erreur SSL
    OpenSSL_add_ssl_algorithms();            // Ajout des algorithmes nécessaires

    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method()); // Création du contexte SSL pour le serveur
    if (!ctx) {
        perror("Impossible de créer le contexte SSL");
        exit(EXIT_FAILURE);
    }

    // Chargement du certificat et de la clé privée
    if (SSL_CTX_use_certificate_file(ctx, "server.crt", SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(ctx, "server.key", SSL_FILETYPE_PEM) <= 0) {
        perror("Erreur lors du chargement des certificats SSL.");
        exit(EXIT_FAILURE);
    }

    // Validation de la clé privée
    if (!SSL_CTX_check_private_key(ctx)) {
        perror("La clé privée ne correspond pas au certificat public.");
        exit(EXIT_FAILURE);
    }

    return ctx;  // Retourne le contexte SSL
}

// Nettoyage des ressources SSL
void cleanup_ssl(SSL_CTX *ctx) {
    SSL_CTX_free(ctx);   // Libération du contexte SSL
    EVP_cleanup();       // Nettoyage des bibliothèques OpenSSL
}

// Gestion des signaux pour une fermeture propre
void handle_signal(int signal) {
    printf("\nFermeture du serveur...\n");
    cleanup_ssl(NULL);  // Nettoyage des ressources SSL
    exit(0);
}

// Structure représentant un client
typedef struct {
    SSL *ssl;            // SSL pour le chiffrement des communications
    char username[50];   // Nom d'utilisateur du client
} Client;

// Tableau pour stocker les clients connectés
Client *clients[MAX_CLIENTS];
pthread_mutex_t clients_mutex = PTHREAD_MUTEX_INITIALIZER;  // Mutex pour synchroniser l'accès aux clients

// Fonction de journalisation (pour le débogage et la surveillance)
void log_event(const char *event) {
    FILE *log_file = fopen("server.log", "a");
    if (log_file != NULL) {
        fprintf(log_file, "%s\n", event);
        fclose(log_file);
    }
}

// Fonction pour diffuser un message à tous les clients sauf l'expéditeur
void broadcast_message(char *message, Client *sender) {
    pthread_mutex_lock(&clients_mutex);
    for (int i = 0; i < MAX_CLIENTS; ++i) {
        if (clients[i] != NULL && clients[i] != sender) {
            char formatted_message[BUFFER_SIZE + 50];
            // Prépare le message pour les autres clients
            snprintf(formatted_message, sizeof(formatted_message), "%s : %s", sender->username, message);

            if (SSL_write(clients[i]->ssl, formatted_message, strlen(formatted_message)) <= 0) {
                perror("Erreur lors de l'envoi du message.");
            }
        }
    }
    pthread_mutex_unlock(&clients_mutex);
}

void send_to_self(char *message, Client *sender) {
    char formatted_message[BUFFER_SIZE + 50];
    // Prépare le message pour soi-même
    snprintf(formatted_message, sizeof(formatted_message), "Moi : %s", message);

    if (SSL_write(sender->ssl, formatted_message, strlen(formatted_message)) <= 0) {
        perror("Erreur lors de l'envoi du message à soi-même.");
    }
}

// Fonction pour retirer un client de la liste
void remove_client(Client *client) {
    pthread_mutex_lock(&clients_mutex);
    for (int i = 0; i < MAX_CLIENTS; ++i) {
        if (clients[i] == client) {
            clients[i] = NULL;  // Suppression du client
            break;
        }
    }
    pthread_mutex_unlock(&clients_mutex);

    SSL_free(client->ssl);  // Libération des ressources SSL
    free(client);           // Libération de la mémoire du client
}

// Fonction pour gérer un client
void *handle_client(void *arg) {
    char buffer[BUFFER_SIZE];
    char message[BUFFER_SIZE];
    Client *client = (Client *)arg;

    snprintf(message, sizeof(message), "%s a rejoint la discussion.", client->username);
    printf("%s\n", message);
    log_event(message);
    broadcast_message(message, client);

    // Envoie un message de bienvenue au client
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

            // Envoie le message à soi-même
            send_to_self(buffer, client);
            // Diffuse le message aux autres clients
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
    return NULL;
}

// Fonction pour ajouter un client à la liste
int add_client(Client *client) {
    pthread_mutex_lock(&clients_mutex);
    for (int i = 0; i < MAX_CLIENTS; ++i) {
        if (clients[i] == NULL) {
            clients[i] = client;
            pthread_mutex_unlock(&clients_mutex);
            return 0;  // Succès
        }
    }
    pthread_mutex_unlock(&clients_mutex);
    return -1;  // Échec, tableau plein
}

int main() {
    int server_socket, client_socket;
    struct sockaddr_in server_addr, client_addr;
    socklen_t addr_len = sizeof(client_addr);
    pthread_t tid;

    SSL_CTX *ctx = initialize_ssl();  // Initialisation du contexte SSL

    // Création du socket serveur
    if ((server_socket = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("Échec de la création du socket.");
        exit(EXIT_FAILURE);
    }

    // Configuration de l'adresse du serveur
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    // Liaison du socket à l'adresse
    if (bind(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Erreur lors du bind.");
        exit(EXIT_FAILURE);
    }

    // Mise en écoute des connexions
    if (listen(server_socket, 10) < 0) {
        perror("Erreur lors du listen.");
        exit(EXIT_FAILURE);
    }

    // Gestion des signaux pour une fermeture propre
    signal(SIGINT, handle_signal);  // Capture CTRL+C

    printf("Serveur en attente de connexions sur le port %d...\n", PORT);

    // Boucle pour accepter et gérer les connexions clients
    while (1) {
        if ((client_socket = accept(server_socket, (struct sockaddr *)&client_addr, &addr_len)) < 0) {
            perror("Erreur lors de l'accept.");
            exit(EXIT_FAILURE);
        }

        SSL *ssl = SSL_new(ctx);           // Création de la session SSL
        SSL_set_fd(ssl, client_socket);    // Association de la session SSL au socket client
        if (SSL_accept(ssl) <= 0) {       // Négociation SSL avec le client
            ERR_print_errors_fp(stderr);
            close(client_socket);
            SSL_free(ssl);
            continue;
        }

        // Création d'un nouvel objet Client
        Client *client = (Client *)malloc(sizeof(Client));
        if (client == NULL) {
            perror("Erreur d'allocation mémoire pour le client.");
            close(client_socket);
            SSL_free(ssl);
            continue;
        }
        client->ssl = ssl;

        // Lecture du nom d'utilisateur envoyé par le client
        SSL_read(ssl, client->username, 50);
        client->username[49] = '\0';  // S'assurer que le nom est bien terminé

        if (strlen(client->username) == 0) {
            printf("Connexion refusée : nom d'utilisateur vide.\n");
            SSL_shutdown(ssl);
            SSL_free(ssl);
            close(client_socket);
            free(client);
            continue;
        }

        printf("%s s'est connecté.\n", client->username);
        log_event(client->username);

        // Ajout du client à la liste des clients connectés
        if (add_client(client) < 0) {
            printf("Serveur plein, connexion refusée pour %s.\n", client->username);
            SSL_shutdown(ssl);
            SSL_free(ssl);
            close(client_socket);
            free(client);
            continue;
        }

        // Création du thread pour gérer ce client
        pthread_create(&tid, NULL, handle_client, (void *)client);
        pthread_detach(tid);  // Détacher le thread pour qu'il se nettoie automatiquement
    }

    close(server_socket);
    cleanup_ssl(ctx);
    return 0;
}
