#include "utils.h"

void parse_usernames(const char *input, char usernames[][NAME], int *count) {
	*count = 0;
	const char *start = input;
	const char *end = input;

	while (*start) {
		// Skip spaces
		if (*start == ' ') {
			start++;
		}
		if (*start == '\0') break;
		// Find the end of the username
		end = start;
		while (*end != ' ' && *end != '\0')
			end++;
		// Copy the username into the array
		int length = end - start;
		if (length >= NAME)
			length = NAME - 1;

		memcpy(usernames[*count], start, length);
		usernames[*count][length] = '\0';
		usernames[*count][length] = '\0';
		(*count)++;
		start = end;
	}
}