#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "consts.h"
#include "io.h"
#include "security.h"

int state_sec = 0;              // Current state for handshake
uint8_t nonce[NONCE_SIZE];      // Store generated nonce to verify signature
uint8_t peer_nonce[NONCE_SIZE]; // Store peer's nonce to sign

void init_sec(int initial_state) {
    state_sec = initial_state;
    init_io();

    // Comment out the below to work like Project 1
    if (state_sec == CLIENT_CLIENT_HELLO_SEND) {
        generate_private_key();
        derive_public_key();
        derive_self_signed_certificate();
        load_ca_public_key("ca_public_key.bin");
    } else if (state_sec == SERVER_CLIENT_HELLO_AWAIT) {
        load_certificate("server_cert.bin");
        load_private_key("server_key.bin");
        derive_public_key();
    } 
      
    generate_nonce(nonce, NONCE_SIZE);
}

ssize_t input_sec(uint8_t* buf, size_t max_length) {
    // This passes it directly to standard input (working like Project 1)
    //return input_io(buf, max_length);
    int max_plaintext = ((int)(max_length - PLAINTEXT_OFFSET) / 16) * 16 - 1;

    switch (state_sec) {
    case CLIENT_CLIENT_HELLO_SEND: {
        print("SEND CLIENT HELLO");

        /* Insert Client Hello sending logic here */
        // Type 
        buf[0] = CLIENT_HELLO; 
        // Length (1 byte for type + 2 bytes for length + NONCE_SIZE for value) 
        uint16_t outer_length = htons(1 + 2 + NONCE_SIZE);
        memcpy(buf + 1, &outer_length, sizeof(outer_length)); 

        // Nested TLV for nonce
        buf[3] = NONCE_CLIENT_HELLO;
        uint16_t inner_length = htons(NONCE_SIZE);
        memcpy(buf + 4, &inner_length, sizeof(inner_length));
        memcpy(buf + 6, &nonce, NONCE_SIZE);

        state_sec = CLIENT_SERVER_HELLO_AWAIT;
        //print_tlv(buf, 6 + NONCE_SIZE);
        return 1 + 2 + 1 + 2 + NONCE_SIZE; // Accounts for the two TLV headers
    }
    case SERVER_SERVER_HELLO_SEND: {
        print("SEND SERVER HELLO");

        /* Insert Server Hello sending logic here */
        int index = 0;
        buf[index] = SERVER_HELLO;
        uint16_t server_hello_length = 0;

        // Nonce
        index += 3;
        buf[index] = NONCE_SERVER_HELLO;
        uint16_t nonce_length = htons(NONCE_SIZE);
        memcpy(buf + index + 1, &nonce_length, sizeof(nonce_length));
        memcpy(buf + index + 3, &nonce, NONCE_SIZE);

        // Certificate
        index += 3 + NONCE_SIZE;
        //print_tlv(certificate, cert_size);
        memcpy(buf + index, certificate, cert_size);

        // Nonce Signature
        index += cert_size;
        buf[index] = NONCE_SIGNATURE_SERVER_HELLO;
        int8_t* signature = malloc(72);
        uint16_t signature_length = sign(peer_nonce, sizeof(peer_nonce), signature);
        uint16_t signature_length_network = htons(signature_length);
        memcpy(buf + index + 1, &signature_length_network, sizeof(signature_length_network));
        memcpy(buf + index + 3, signature, signature_length);

        server_hello_length = htons(3 + NONCE_SIZE + cert_size + 3 + signature_length);
        memcpy(buf + 1, &server_hello_length, sizeof(server_hello_length));

        state_sec = SERVER_KEY_EXCHANGE_REQUEST_AWAIT;
        //print_tlv(buf, 3 + (3 + NONCE_SIZE) + (cert_size) + (3 + signature_length));
        free(signature);
        return 3 + (3 + NONCE_SIZE) + (cert_size) + (3 + signature_length);
    }
    case CLIENT_KEY_EXCHANGE_REQUEST_SEND: {
        print("SEND KEY EXCHANGE REQUEST");

        /* Insert Key Exchange Request sending logic here */
        int index = 0;
        buf[index] = KEY_EXCHANGE_REQUEST;
        uint16_t key_exchange_request_length = 0;

        // Certificate
        index += 3;
        memcpy(buf + index, certificate, cert_size);

        // Nonce Signature
        index += cert_size;
        buf[index] = NONCE_SIGNATURE_KEY_EXCHANGE_REQUEST;
        int8_t* nonce_signature = malloc(72);   // Max nonce signature size
        uint16_t nonce_signature_length = sign(peer_nonce, sizeof(peer_nonce), nonce_signature);
        uint16_t nonce_signature_length_network = htons(nonce_signature_length);
        memcpy(buf + index + 1, &nonce_signature_length_network, sizeof(nonce_signature_length_network));
        memcpy(buf + index + 3, nonce_signature, nonce_signature_length);

        key_exchange_request_length = htons(cert_size + 3 + nonce_signature_length);
        memcpy(buf + 1, &key_exchange_request_length, sizeof(key_exchange_request_length));

        state_sec = CLIENT_FINISHED_AWAIT;
        return 3 + (cert_size) + (3 + nonce_signature_length);
    }
    case SERVER_FINISHED_SEND: {
        print("SEND FINISHED");

        /* Insert Finished sending logic here */
        buf[0] = FINISHED;
        uint16_t length = htons(0);
        memcpy(buf + 1, &length, sizeof(length)); 

        state_sec = DATA_STATE;
        return 1 + 2;
    }
    case DATA_STATE: {
        /* Insert Data sending logic here */

        int index = 0;
        buf[index] = DATA;
        uint16_t data_length = 0;

        uint8_t* initialization_vector = malloc(IV_SIZE);
        uint8_t* plaintext = malloc(max_plaintext);
        uint8_t* ciphertext = malloc(max_plaintext);
        // Read from standard input
        uint16_t plaintext_length = input_io(plaintext, max_plaintext);

        if(plaintext_length <= 0){
            free(initialization_vector);
            free(plaintext);
            free(ciphertext);
            return 0;
        }

        // Encrypt
        uint16_t ciphertext_length = encrypt_data(plaintext, plaintext_length, initialization_vector, ciphertext);

        // Generate HMAC digest
        uint8_t* digest = malloc(MAC_SIZE);
        uint16_t iv_and_ciphertext_length = IV_SIZE + ciphertext_length;
        uint8_t* iv_and_ciphertext = malloc(iv_and_ciphertext_length);
        memcpy(iv_and_ciphertext, initialization_vector, IV_SIZE);
        memcpy(iv_and_ciphertext + IV_SIZE, ciphertext, ciphertext_length);
        hmac(iv_and_ciphertext, iv_and_ciphertext_length, digest);

        // Initialization Vector
        index += 3;
        buf[index] = INITIALIZATION_VECTOR;
        uint16_t IV_length = htons(IV_SIZE);
        memcpy(buf + index + 1, &IV_length, sizeof(IV_length)); 
        memcpy(buf + index + 3, initialization_vector, IV_SIZE);

        // Ciphertext
        index += 3 + IV_SIZE;
        buf[index] = CIPHERTEXT;
        uint16_t ciphertext_length_network = htons(ciphertext_length);
        memcpy(buf + index + 1, &ciphertext_length_network, sizeof(ciphertext_length_network)); 
        memcpy(buf + index + 3, ciphertext, ciphertext_length);

        // Message Authentication Code
        index += 3 + ciphertext_length;
        buf[index] = MESSAGE_AUTHENTICATION_CODE;
        uint16_t MAC_length = htons(MAC_SIZE);
        memcpy(buf + index + 1, &MAC_length, sizeof(MAC_length)); 
        memcpy(buf + index + 3, digest, MAC_SIZE);
        
        free(iv_and_ciphertext);
        free(digest);
        free(initialization_vector);
        free(plaintext);
        free(ciphertext);

        // PT refers to the amount you read from stdin in bytes
        long int PT = plaintext_length;
        // CT refers to the resulting ciphertext size
        unsigned long int CT = ciphertext_length;
        fprintf(stderr, "SEND DATA PT %ld CT %lu\n", PT, CT);

        print_tlv(buf, 3 + (3 + IV_SIZE) + (3 + ciphertext_length) + (3 + MAC_SIZE));

        return 3 + (3 + IV_SIZE) + (3 + ciphertext_length) + (3 + MAC_SIZE);
    }
    default:
        return 0;
    }
}

void output_sec(uint8_t* buf, size_t length) {
    // This passes it directly to standard output (working like Project 1)
    // return output_io(buf, length);

    switch (state_sec) {
    case SERVER_CLIENT_HELLO_AWAIT: {
        if (*buf != CLIENT_HELLO)
            exit(4);

        print("RECV CLIENT HELLO");

        /* Insert Client Hello receiving logic here */
        memcpy(&peer_nonce, buf + 6, NONCE_SIZE);

        state_sec = SERVER_SERVER_HELLO_SEND;
        break;
    }
    case CLIENT_SERVER_HELLO_AWAIT: {
        if (*buf != SERVER_HELLO){
            printf("Error: Expected SERVER_HELLO, but got %02x\n", *buf);
            exit(4);
        }
        print("RECV SERVER HELLO");

        /* Insert Server Hello receiving logic here */
        // Store nonce in peer_nonce
        memcpy(&peer_nonce, buf + 6, NONCE_SIZE);

        // Get the Server's Public Key (from certificate) (from Server)
        uint16_t server_public_key_length = 0;
        int public_key_index = 3 + 3 + NONCE_SIZE + 3; 
        memcpy(&server_public_key_length, buf + public_key_index + 1, sizeof(uint16_t));
        server_public_key_length = ntohs(server_public_key_length);

        uint8_t* server_public_key = malloc(server_public_key_length);
        memcpy(server_public_key, buf + public_key_index + 3, server_public_key_length);

        // Get the Signature (from certificate) (from Server)
        uint16_t signature_length = 0;
        int signature_index = 3 + 3 + NONCE_SIZE + 3 + 3 + server_public_key_length;
        memcpy(&signature_length, buf + signature_index + 1, sizeof(uint16_t));
        signature_length = ntohs(signature_length);

        uint8_t* signature = malloc(signature_length);
        memcpy(signature, buf + signature_index + 3, signature_length);

        // Verify the certificate signed by a Certificate Authority
        if(1 != verify(server_public_key, server_public_key_length, signature, signature_length, ec_ca_public_key)){
            free(server_public_key); 
            free(signature);
            printf("Exit 1: Certificate verification failed.\n");
            exit(1);    // Failure to verify certificate signed by a Certificate Authority
        }

        // Get the Nonce Signature (from Server)
        uint16_t nonce_signature_length = 0;
        int nonce_signature_index = 3 + 3 + NONCE_SIZE + 3 + 3 + server_public_key_length + 3 + signature_length;
        memcpy(&nonce_signature_length, buf + nonce_signature_index + 1, sizeof(uint16_t));
        nonce_signature_length = ntohs(nonce_signature_length);

        uint8_t* nonce_signature = malloc(nonce_signature_length);
        memcpy(nonce_signature, buf + nonce_signature_index + 3, nonce_signature_length);

        // Verify the Nonce
        load_peer_public_key(server_public_key, server_public_key_length);
        if(1 != verify(nonce, NONCE_SIZE, nonce_signature, nonce_signature_length, ec_peer_public_key)){
            free(server_public_key); 
            free(signature);
            free(nonce_signature);
            printf("Exit 2: Nonce verification failed.\n");
            exit(2);   // Failure to verify client nonce signed by server
        }

        // Generate ENC and MAC keys from client's private key and server's public key
        derive_secret();
        derive_keys();
        
        state_sec = CLIENT_KEY_EXCHANGE_REQUEST_SEND;
        free(server_public_key); 
        free(signature);
        free(nonce_signature);
        break;
    }
    case SERVER_KEY_EXCHANGE_REQUEST_AWAIT: {
        if (*buf != KEY_EXCHANGE_REQUEST)
            exit(4);

        print("RECV KEY EXCHANGE REQUEST");

        /* Insert Key Exchange Request receiving logic here */

        // Get the Server's Public Key (from certificate) (from Client)
        uint16_t client_public_key_length = 0;
        int public_key_index = 3 + 3; 
        memcpy(&client_public_key_length, buf + public_key_index + 1, sizeof(uint16_t));
        client_public_key_length = ntohs(client_public_key_length);

        uint8_t* client_public_key = malloc(client_public_key_length);
        memcpy(client_public_key, buf + public_key_index + 3, client_public_key_length);

        // Get the Signature (from certificate) (from Client)
        uint16_t signature_length = 0;
        int signature_index = 3 + 3 + (3 + client_public_key_length);
        memcpy(&signature_length, buf + signature_index + 1, sizeof(uint16_t));
        signature_length = ntohs(signature_length);

        uint8_t* signature = malloc(signature_length);
        memcpy(signature, buf + signature_index + 3, signature_length);

        load_peer_public_key(client_public_key, client_public_key_length);
        // Verify the certificate was self-signed by the client
        if(1 != verify(client_public_key, client_public_key_length, signature, signature_length, ec_peer_public_key)){
            free(client_public_key); 
            free(signature);
            printf("Exit 1: Certificate verification failed.\n");
            exit(1);    // Failure to verify certificate self-signed by client
        }

        // Get the Nonce Signature (from Client)
        uint16_t nonce_signature_length = 0;
        int nonce_signature_index = 3 + 3 + (3 + client_public_key_length) + (3 + signature_length);
        memcpy(&nonce_signature_length, buf + nonce_signature_index + 1, sizeof(uint16_t));
        nonce_signature_length = ntohs(nonce_signature_length);

        uint8_t* nonce_signature = malloc(nonce_signature_length);
        memcpy(nonce_signature, buf + nonce_signature_index + 3, nonce_signature_length);

        // Verify the Server Nonce was signed by the client
        if(1 != verify(nonce, NONCE_SIZE, nonce_signature, nonce_signature_length, ec_peer_public_key)){
            free(client_public_key); 
            free(signature);
            free(nonce_signature);
            printf("Exit 2: Nonce verification failed.\n");
            exit(2);   // Failure to verify server nonce signed by client
        }

        // Generate ENC and MAC keys from client's public key and server's private key
        derive_secret();
        derive_keys();

        state_sec = SERVER_FINISHED_SEND;
        free(client_public_key); 
        free(signature);
        free(nonce_signature);
        break;
    }
    case CLIENT_FINISHED_AWAIT: {
        if (*buf != FINISHED)
            exit(4);

        print("RECV FINISHED");

        state_sec = DATA_STATE;
        break;
    }
    case DATA_STATE: {
        if (*buf != DATA){
            exit(4);
        }

        /* Insert Data receiving logic here */
        // Get IV 
        uint16_t IV_length = 0;
        int IV_index = 3; 
        memcpy(&IV_length, buf + IV_index + 1, sizeof(uint16_t));
        IV_length = ntohs(IV_length);

        uint8_t* initialization_vector = malloc(IV_length);
        memcpy(initialization_vector, buf + IV_index + 3, IV_length);

        // Get Ciphertext
        uint16_t ciphertext_length = 0;
        int ciphertext_index = 3 + (3 + IV_length);
        memcpy(&ciphertext_length, buf + ciphertext_index + 1, sizeof(uint16_t));
        ciphertext_length = ntohs(ciphertext_length);

        uint8_t* ciphertext = malloc(ciphertext_length);
        memcpy(ciphertext, buf + ciphertext_index + 3, ciphertext_length);

        // Calculate hmac
        uint8_t* calculated_digest = malloc(MAC_SIZE);
        u_int16_t iv_and_ciphertext_length = IV_SIZE + ciphertext_length;
        uint8_t* iv_and_ciphertext = malloc(iv_and_ciphertext_length);
        memcpy(iv_and_ciphertext, initialization_vector, IV_SIZE);
        memcpy(iv_and_ciphertext + IV_SIZE, ciphertext, ciphertext_length);
        hmac(iv_and_ciphertext, iv_and_ciphertext_length, calculated_digest);

        // Get HMAC digest
        uint16_t digest_length = 0;
        int digest_index = 3 + (3 + IV_length) + (3 + ciphertext_length);
        memcpy(&digest_length, buf + digest_index + 1, sizeof(uint16_t));
        digest_length = ntohs(digest_length);

        uint8_t* digest = malloc(digest_length);
        memcpy(digest, buf + digest_index + 3, digest_length);

        // Compare MAC digests
        if(0 != memcmp(digest, calculated_digest, digest_length)){
            printf("Exit 3: MAC digests do not match.\n");
            free(initialization_vector);
            free(ciphertext);
            free(calculated_digest);
            free(iv_and_ciphertext);
            free(digest);
            exit(3);
        }

        // Decrypt
        uint8_t* plaintext = malloc(MAX_PAYLOAD);
        uint16_t plaintext_length = decrypt_cipher(ciphertext, ciphertext_length, initialization_vector, plaintext);

        // Print to standard output
        output_io(plaintext, plaintext_length);

        // PT refers to the resulting plaintext size in bytes
        long int PT = plaintext_length;
        // CT refers to the received ciphertext size
        int CT = ciphertext_length;
        fprintf(stderr, "RECV DATA PT %ld CT %hu\n", PT, CT);

        free(initialization_vector);
        free(ciphertext);
        free(digest);
        free(calculated_digest);
        free(iv_and_ciphertext);
        free(plaintext);
        break;
    }
    default:
        break;
    }
}


ssize_t input_no_sec(uint8_t* buf, size_t max_length) {
    // This passes it directly to standard input (working like Project 1)
    return input_io(buf, max_length);
}

void output_no_sec(uint8_t* buf, size_t length) {
    // This passes it directly to standard output (working like Project 1)
    return output_io(buf, length);
}