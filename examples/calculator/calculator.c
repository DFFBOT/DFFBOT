#include <stdio.h>
#include <stdlib.h>

// Calculator functions

int divide(int a, int b) {
        return a / b;
}

int multiply(int a, int b) {
        return a * b;
}

int add(int a, int b) {
        return a + b;
}

int subtract(int a, int b) {
        return a - b;
}

int main(int argc, char** argv) {
        // Check the supplied arguments
        if (argc != 4) {
                printf("Not enough arguments!\n");
                printf("Usage: %s <Operation> <Number> <Number>\n", argv[0]);
                return 1;
        }

        // Grab them
        char* operation = argv[1];
        char* firstSubject = argv[2];
        char* secondSubject = argv[3];

        // Debug
        /*
        printf("\n");
        printf("Operation: %s\n", operation);
        printf("First Subject: %s\n", firstSubject);
        printf("Second Subject: %s\n", secondSubject);
        printf("\n");
        */

        // Parsing
        int result = 0;
        int firstSubjectParsed = atoi(firstSubject);
        int secondSubjectParsed = atoi(secondSubject);
        switch(operation[0]) {
                case '-':
                        result = subtract(firstSubjectParsed, secondSubjectParsed);
                        break;

                case '+':
                        result = add(firstSubjectParsed, secondSubjectParsed);
                        break;

                case '*':
                        result = multiply(firstSubjectParsed, secondSubjectParsed);
                        break;

                case '/':
                      result = divide(firstSubjectParsed, secondSubjectParsed);
                      break;

                default:
                        printf("Could not parse operation :-/\n");
                        printf("Allowed operations: '-', '+', '/', '*'\n");
                        return 1;
                        break;
        }
        printf("Result: %d\n", result);
}

