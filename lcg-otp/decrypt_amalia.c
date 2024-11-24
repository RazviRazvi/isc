#include <openssl/bio.h>
#include <openssl/evp.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define NUM_THREADS 8
#define FLAG_INDICATOR "SpeishFlag{"
#define LOWER_BOUND 1337
#define UPPER_BOUND 10000

typedef struct {
  int start_range;
  int end_range;
  uint8_t *encrypted_data;
  size_t data_length;
} WorkerArgs;

//XOR pentru decriptare
void perform_xor(uint8_t *result, const uint8_t *data, const uint8_t *key,
                 size_t length) {
  for (size_t i = 0; i < length; i++) {
    result[i] = data[i] ^ key[i];
  }
}

//generare valori succesive 
uint16_t generate_lcg(uint16_t *current_state, int multiplier, int increment) {
  *current_state = (*current_state * multiplier + increment) % 65536;
  return *current_state;
}

//decodare Base64
uint8_t *decode_base64(const char *encoded_text, size_t *decoded_length) {
  BIO *bio_chain, *b64_filter;
  size_t encoded_length = strlen(encoded_text);
  uint8_t *decoded_buffer = malloc(encoded_length);

  bio_chain = BIO_new_mem_buf(encoded_text, -1);
  b64_filter = BIO_new(BIO_f_base64());
  BIO_set_flags(b64_filter, BIO_FLAGS_BASE64_NO_NL);
  bio_chain = BIO_push(b64_filter, bio_chain);

  *decoded_length = BIO_read(bio_chain, decoded_buffer, encoded_length);
  BIO_free_all(bio_chain);
  return decoded_buffer;
}

//verific daca textul contine indicatorul flag-ului 
bool contains_flag(const char *text) {
  return strstr(text, FLAG_INDICATOR) != NULL;
}

//incercarea unei combinatii de parametri (multiplier, increment)
bool try_decrypt(int multiplier, int increment, uint8_t *ciphertext,
                 size_t length) {
  uint8_t *key_buffer = malloc(length);
  uint8_t *decrypted_text = malloc(length + 1);
  uint16_t lcg_state = 0;

  //genereaza cheia
  for (size_t i = 0; i < length / 2; i++) {
    uint16_t value = generate_lcg(&lcg_state, multiplier, increment);
    key_buffer[2 * i] = value & 0xFF;
    key_buffer[2 * i + 1] = value >> 8;
  }

  //decriptare text
  perform_xor(decrypted_text, ciphertext, key_buffer, length);
  decrypted_text[length] = '\0';  // Adaugă terminator pentru string

  bool flag_found = contains_flag((const char *)decrypted_text);
  if (flag_found) {
    printf("Flag găsit: %s\n", decrypted_text);
  }

  free(key_buffer);
  free(decrypted_text);
  return flag_found;
}

void *worker_function(void *arguments) {
  WorkerArgs *args = (WorkerArgs *)arguments;

  for (int multiplier = args->start_range; multiplier < args->end_range;
       multiplier++) {
    for (int increment = LOWER_BOUND; increment <= UPPER_BOUND; increment++) {
      if (try_decrypt(multiplier, increment, args->encrypted_data,
                      args->data_length)) {
        exit(0);  //flag gasit
      }
    }
  }
  return NULL;
}

int main() {

  FILE *input_file = fopen("cypher.txt", "r");
  if (!input_file) {
    perror("Eroare la deschiderea fișierului cypher.txt");
    return EXIT_FAILURE;
  }

  char encoded_text[4096];
  if (!fgets(encoded_text, sizeof(encoded_text), input_file)) {
    perror("Eroare la citirea fișierului");
    fclose(input_file);
    return EXIT_FAILURE;
  }
  fclose(input_file);

  //decodare
  size_t data_length;
  uint8_t *ciphertext = decode_base64(encoded_text, &data_length);

  //creare + lansare thread
  pthread_t thread_pool[NUM_THREADS];
  WorkerArgs thread_args[NUM_THREADS];
  int step = (UPPER_BOUND - LOWER_BOUND) / NUM_THREADS;

  for (int i = 0; i < NUM_THREADS; i++) {
    thread_args[i].start_range = LOWER_BOUND + i * step;
    thread_args[i].end_range =
        (i == NUM_THREADS - 1) ? UPPER_BOUND + 1 : LOWER_BOUND + (i + 1) * step;
    thread_args[i].encrypted_data = ciphertext;
    thread_args[i].data_length = data_length;
    pthread_create(&thread_pool[i], NULL, worker_function, &thread_args[i]);
  }

  for (int i = 0; i < NUM_THREADS; i++) {
    pthread_join(thread_pool[i], NULL);
  }

  free(ciphertext);
  return EXIT_SUCCESS;
}