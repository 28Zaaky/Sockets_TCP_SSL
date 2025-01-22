# Socket TCP sécurisé en C

## Description

Ce projet implémente un serveur TCP sécurisé en C, utilisant OpenSSL pour garantir des communications SSL/TLS entre le serveur et ses clients. Le serveur est conçu pour gérer plusieurs connexions simultanées grâce à la gestion des threads, et il existe deux versions du serveur : une pour Windows et une pour Unix (Linux/Mac). Le projet inclut également un client Python permettant d’échanger des messages.

## Fonctionnement

### Serveur

Le serveur gère plusieurs clients en parallèle à l'aide de threads. Chaque connexion est sécurisée avec SSL/TLS (auto signé ici)pour chiffrer les échanges. Le serveur transmet les messages reçus d'un client à tous les autres clients connectés, sauf à l'expéditeur. Il fonctionne en mode multi-clients, permettant à plusieurs utilisateurs de discuter simultanément.

### Client

Le client Python se connecte au serveur via un socket TCP. Après s'être authentifié en envoyant un nom d'utilisateur, le client peut envoyer et recevoir des messages en temps réel. Il peut quitter la session avec la commande `/quit`.

### Architecture réseau

Le serveur utilise des sockets TCP pour établir des connexions avec les clients. Chaque client est géré par un thread, ce qui permet de maintenir une communication fluide et simultanée entre plusieurs utilisateurs. Les messages sont envoyés et reçus en temps réel, garantissant une messagerie interactive et sécurisée.

## Prérequis

Pour exécuter ce projet, vous aurez besoin des fichiers suivants :
- **server.crt** : Certificat SSL pour le serveur.
- **server.key** : Clé privée SSL du serveur.

Ces fichiers doivent être présents dans le même répertoire que le serveur. Vous pouvez générer un certificat et une clé privée auto-signés pour un environnement de test.
