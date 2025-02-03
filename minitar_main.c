#include <stdio.h>
#include <string.h>

#include "file_list.h"
#include "minitar.h"

int main(int argc, char **argv) {
    if (argc < 4) {
        printf("Usage: %s -c|a|t|u|x -f ARCHIVE [FILE...]\n", argv[0]);
        return 0;
    }

    file_list_t files;
    file_list_init(&files);

    // TODO: Parse command-line arguments and invoke functions from 'minitar.h'
    // to execute archive operations
    // From this code, we know that argv[0] is the program name, argv[1] is the operation flag, 
    // argv[2] is the flag of the file and argv[3] is the archive filename.
    // We know argv[0] and argv[2] is the same everytime so no need to define them.

    char *operation = argv[1];
    char *archive = argv[3];

    for (int i = 4; i < argc; i++) {
        // Checks for valid archive command.
        if (file_list_add(&files, argv[i]) != 0) { 
            fprintf(stderr, "Error adding file: %s\n", argv[i]);
            file_list_clear(&files); // Clears invalid file(s).
            return 1; // Returns 1, indicating error.
        }
    }
    int result = 0;
    if (strcmp(operation, "-c") == 0) { // Creates archive.
        result = minitar_create(archive, &files);
    } else if (strcmp(operation, "-a") == 0) { // Adds new files to a archive.
        result = minitar_append(archive, &files);
    } else if (strcmp(operation, "-t") == 0) { // Lists files in archive.
        result = minitar_list(archive);
    } else if (strcmp(operation, "-u") == 0) { // Replaces the old files of an archive with new ones.
        result = minitar_update(archive, &files);
    } else if (strcmp(operation, "-x") == 0) { // Moves all files in a given archive and moves it to the current directory.
        result = minitar_extract(archive);
    } else { // Invalid operation given.
        fprintf(stderr, "Invalid operation: %s\n", operation);
        file_list_clear(&files);
        return 1;
    }

    // Check for errors.
    if (result != 0) { // Not 0, aka an error was produced. 
        fprintf(stderr, "Operation failed: %s\n", operation);
        file_list_clear(&files);
        return 1;
    }

    // Print filenames for archive list operation
    if (strcmp(operation, "-t") == 0) {
        file_list_print(&files);  // Print the filenames.
                                  // We just do this to -t because it's the only one
                                  // that prints out anything.
    }

    // Cleanup.
    file_list_clear(&files); // This code was given
    return 0;
}
