
/* Various generic C helper functions */
/* sivann */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

//replace occurences of old with new in null terminated string s
void str_replace_char_inline(char * s, char old, char new) {
    char *p = s;

    while(*p) {
        if(*p == old)
        *p = new;
        ++p;
    }
}

/*
 * Create a new string with [substr] being replaced by [replacement] in [string]
 * Returns the new string, or NULL if out of memory.
 * The caller is responsible for freeing the new returned string.
 *
 */
char *str_replace (const char *string, const char *substr, const char *replacement) {
    char *tok = NULL;
    char *newstr = NULL;

    tok = strstr (string, substr);

    if (tok == NULL)
        return strdup (string);

    newstr = malloc (strlen (string) - strlen (substr) + strlen (replacement) + 1);

    if (newstr == NULL)
        return NULL;

    memcpy (newstr, string, tok - string);
    memcpy (newstr + (tok - string), replacement, strlen (replacement) );
    memcpy (newstr + (tok - string) + strlen (replacement),
            tok + strlen (substr),
            strlen (string) - strlen (substr) - (tok - string) );
    memset (newstr + strlen (string) - strlen (substr) + strlen (replacement), 0, 1);

    return newstr;
}

/* caller responsible for memory */
/* strlen(enc) <= strlen(s)*3+1 */
void url_encode (const char *s, char *enc, char *tb) {
    for (; *s; s++) {
        if (tb[ (unsigned char) *s]) sprintf (enc, "%c", tb[ (unsigned char) *s]);
        else        sprintf (enc, "%%%02X", *s);
        while (*++enc);
    }
}

void url_encode_init (char *tb) {
    int i;
    for (i = 0; i < 256; i++) {
        /*
        rfc3986[i] = isalnum(i)||i == '~'||i == '-'||i == '.'||i == '_'
            ? i : 0;
        */
        tb[i] = isalnum (i) ||i == '*'||i == '-'||i == '.'||i == '_'
                ? i : (i == ' ') ? '+' : 0;
    }

}

//dump hex and text dump of *ptr
void dump (const char *text, FILE *stream, unsigned char *ptr, size_t size) {
    size_t i;
    size_t c;
    unsigned int width=0x10;

    fprintf (stream, "%s, %10.10ld bytes (0x%8.8lx)\n", text, (long) size, (long) size);

    for (i=0; i<size; i+= width) {
        fprintf (stream, "%4.4lx: ", (long) i);

        /* show hex to the left */
        for (c = 0; c < width; c++) {
            if (i+c < size)
                fprintf (stream, "%02x ", ptr[i+c]);
            else
                fputs ("   ", stream);
        }

        /* show data on the right */
        for (c = 0; (c < width) && (i+c < size); c++)
            fputc ( (ptr[i+c]>=0x20) && (ptr[i+c]<0x80) ?ptr[i+c]:'.', stream);

        fputc ('\n', stream); /* newline */
    }
}


//strlen the trimmed string (strlen no whitespace). Does not modify string.
int strlen_no_ws (char *str) {
    char *end;

    // leading space
    while (isspace (*str) ) str++;

    if (*str == 0) // All spaces?
        return 0;

    // trailing space
    end = str + strlen (str) - 1;
    while (end > str && isspace (*end) ) end--;

    return end-str;
}

/* checks if string s contains any of the specified chars. Returns 1 on found*/
int contains_chars(char * s, char * chars) {
    char found = 0;
    unsigned int i;

    for (i = 0; i < strlen(chars); ++i) {
        if (strchr(s, chars[i]) != NULL) {
            found = 1;
            break;
        }
    }

    if (found) {
        return 1;
    }
    return 0;
}

