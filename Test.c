#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// On définit ici la variable globale "variables" qui sera utilisée par build_multipart_body.
// On suppose qu'elle contient des paires clé=valeur séparées par '&'.
// Pour ce test, on utilise par exemple :
char *variables = "username=testuser&password=testpass";

// La fonction build_multipart_body construit le corps d'une requête multipart/form-data
// à partir de la chaîne globale "variables" et du boundary fourni.
char *build_multipart_body(char *multipart_boundary) {
    if (!variables)
        return NULL;  // Pas de paramètres à traiter

    char *body = NULL;      // Chaîne résultat
    size_t body_size = 0;   // Taille actuelle du corps

    // Dupliquer la chaîne "variables" afin de pouvoir la tokeniser (strtok modifie la chaîne)
    char *vars_dup = strdup(variables);
    if (!vars_dup)
        return NULL;

    // Tokeniser la chaîne sur le caractère '&'
    char *pair = strtok(vars_dup, "&");
    while (pair != NULL) {
        // Pour chaque paire, rechercher le séparateur '='
        char *equal_sign = strchr(pair, '=');
        if (!equal_sign) {
            pair = strtok(NULL, "&");
            continue;
        }
        *equal_sign = '\0';  // Terminer la clé
        char *key = pair;
        char *value = equal_sign + 1;

        // Construire la section multipart pour ce champ.
        // Format attendu :
        // --<boundary>\r\n
        // Content-Disposition: form-data; name="<key>"\r\n
        // \r\n
        // <value>\r\n
        int section_len = snprintf(NULL, 0,
            "--%s\r\n"
            "Content-Disposition: form-data; name=\"%s\"\r\n"
            "\r\n"
            "%s\r\n",
            multipart_boundary, key, value);

        char *section = malloc(section_len + 1);
        if (!section) {
            free(body);
            free(vars_dup);
            return NULL;
        }
        snprintf(section, section_len + 1,
            "--%s\r\n"
            "Content-Disposition: form-data; name=\"%s\"\r\n"
            "\r\n"
            "%s\r\n",
            multipart_boundary, key, value);

        // Réallouer le buffer "body" pour y ajouter cette section
        size_t new_body_size = body_size + section_len;
        char *new_body = realloc(body, new_body_size + 1); // +1 pour le '\0'
        if (!new_body) {
            free(section);
            free(body);
            free(vars_dup);
            return NULL;
        }
        body = new_body;
        if (body_size == 0)
            strcpy(body, section);
        else
            strcat(body, section);
        body_size = new_body_size;
        free(section);

        // Passage à la paire suivante
        pair = strtok(NULL, "&");
    }
    free(vars_dup);

    // Ajouter la fermeture du multipart :
    // --<boundary>--\r\n
    int closing_len = snprintf(NULL, 0, "--%s--\r\n", multipart_boundary);
    char *closing = malloc(closing_len + 1);
    if (!closing) {
        free(body);
        return NULL;
    }
    snprintf(closing, closing_len + 1, "--%s--\r\n", multipart_boundary);

    size_t final_size = body_size + closing_len;
    char *final_body = realloc(body, final_size + 1);
    if (!final_body) {
        free(closing);
        free(body);
        return NULL;
    }
    body = final_body;
    strcat(body, closing);
    free(closing);

    return body;
}

int main(void) {
    // Définir un boundary pour le test
    char boundary[] = "----THC-HydraBoundaryz2Z2z";
    // Appeler la fonction build_multipart_body
    char *multipart_body = build_multipart_body(boundary);
    if (multipart_body == NULL) {
        fprintf(stderr, "Error building multipart body.\n");
        return 1;
    }
    // Afficher le corps multipart généré
    printf("Multipart body:\n%s\n", multipart_body);
    free(multipart_body);
    return 0;
}
