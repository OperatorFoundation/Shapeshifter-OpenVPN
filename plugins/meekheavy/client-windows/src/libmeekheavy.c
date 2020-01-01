#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <libmeekheavy.h>

#define CURL_STATICLIB 1
#include <curl/curl.h>

CURL *curl;
CURLcode res;

struct MemoryStruct { //define structure
    char *memory;
    size_t size;
};

struct MemoryStruct chunk; //create instance of structure to store return data




 uint8_t initESNI(char *URL, char *serverESNI, char *coverESNI, char *keyESNI )
{
    //setup esni connection, pass vars to function, return 0 on success 1 on fail

    chunk.memory = malloc(1);  /* will be grown as needed by the realloc  in curlWriteFunction*/
    chunk.size = 0;    /* no data at this point */

    curl_global_init(CURL_GLOBAL_DEFAULT);

    curl = curl_easy_init();
    if (curl) {
        //curl_easy_setopt();

        curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
        curl_easy_setopt(curl, CURLOPT_IPRESOLVE, CURL_IPRESOLVE_V4); //force ipv4, ipv6 seems to not work on test server 2019.12.18
        curl_easy_setopt(curl, CURLOPT_URL, URL);
        curl_easy_setopt(curl, CURLOPT_ESNI_STATUS, CURLESNI_ENABLE | CURLESNI_STRICT);
        curl_easy_setopt(curl, CURLOPT_ESNI_SERVER, serverESNI);
        curl_easy_setopt(curl, CURLOPT_ESNI_COVER, coverESNI);
        curl_easy_setopt(curl, CURLOPT_ESNI_ASCIIRR,keyESNI);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *) &chunk);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, &curlWriteFunction);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, -1L);

        char *sessionID = (char *) malloc((16 * 2) + 1);

        int resultCode = sessionIDgen(sessionID);

        if (resultCode == 0) {
            //string2hexString(randomBuffer, hexRandomBuffer, 64);
            printf("SessionID: %s\n", sessionID);

            //return 0;
        } else {
            printf("Not enough random bytes for PRNG");
            return 1;
        }
        char sessionIDheader[(16 * 2) + 1 + 14] = "X-Session-Id: ";
        strcat(sessionIDheader, sessionID);
        printf("sessionheader::  %s\n", sessionIDheader);
        struct curl_slist *list = NULL;
        list = curl_slist_append(list, "User-Agent: ");
        list = curl_slist_append(list, sessionIDheader);
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, list);

        #ifdef SKIP_PEER_VERIFICATION
                /*
             * If you want to connect to a site who isn't using a certificate that is
             * signed by one of the certs in the CA bundle you have, you can skip the
             * verification of the server's certificate. This makes the connection
             * A LOT LESS SECURE.
             *
             * If you have a CA cert for the server stored someplace else than in the
             * default bundle, then the CURLOPT_CAPATH option might come handy for
             * you.
             */
            curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        #endif

        #ifdef SKIP_HOSTNAME_VERIFICATION
                /*
             * If the site you're connecting to uses a different host name that what
             * they have mentioned in their server certificate's commonName (or
             * subjectAltName) fields, libcurl will refuse to connect. You can skip
             * this check, but this will make the connection less secure.
             */
            curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
        #endif
    }

}


uint8_t writeESNI(char *data, size_t *len)
{
    //perform the ESNI connection, send data and receive response into buffer
    //if response code is not 200, don't buffer the data
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, "data data data meh");

    long httpResponseCode = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &httpResponseCode);

    /* Perform the request, res will get the return code */
    res = curl_easy_perform(curl);
    /* Check for errors */
    if(res != CURLE_OK) {
        fprintf(stderr, "curl_easy_perform() failed: %s\n",
                curl_easy_strerror(res));
    }else{
        printf("----THE_RESULTS----\n");
        if (httpResponseCode != 200L){
            //clear buffered data in struct chunk.memory
        }
        printf("%lu bytes retrieved\n", (unsigned long)chunk.size);
        printf("PageData: \n%s", (char*)chunk.memory);
    }


}

uint32_t readESNI(char *returnBuffer,  size_t requestedSize)
{
    //copy requested number of bytes of data from our buffer up to our buffer size, into the passed buffer,
    // and then clear the returned data from our buffer
    //return the number of bytes we actually copied into the returnBuffer
    size_t bytesCopied = 0;

    if (chunk.size <= requestedSize) {
        //requested the same or more bytes than we have so copy it all
        bytesCopied = chunk.size;
        memcpy(returnBuffer, chunk.memory, chunk.size);

        //manage our buffer
        //we copied the whole buffer, so just clear it
        chunk.memory = realloc(chunk.memory, 1);
        chunk.memory = "\0"; //only handy for debug printing
        chunk.size = 0UL;    /* no data at this point */
    }

    if (chunk.size > requestedSize){
        //requested less than we have so only send back what they want
        bytesCopied = requestedSize;
        memcpy(returnBuffer, chunk.memory, requestedSize);

        //manage our buffer
        //we only returned part of our buffer so remove the part that was returned
        memmove(chunk.memory, &chunk.memory[requestedSize], (chunk.size - requestedSize));
        chunk.size = chunk.size - requestedSize;
    }

    return bytesCopied;

}


uint8_t closeESNI()
{
    //close connections and free memory

    /* always cleanup after yourself */
    free(chunk.memory);

    curl_easy_cleanup(curl);
    curl_global_cleanup();

    return 0;
}



size_t curlWriteFunction(void *contents, size_t size, size_t nmemb, void *userp)
{
    long httpResponseCode = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &httpResponseCode);
    size_t realsize = size * nmemb;
    if (httpResponseCode == 200L) { //only copy data into buffer if the http result code is ok (200)

        //we will add the data to the buffer, not overwrite
        struct MemoryStruct *mem = (struct MemoryStruct *) userp; //recast *mem to access user structure since it was passed as a void

        char *ptr = realloc(mem->memory, mem->size + realsize + 1); //resize and copy existing buffer into a newone with more space to handle new data
        if (ptr == NULL) {
            /* out of memory! */
            printf("not enough memory (realloc returned NULL)\n");
            return 0; //tell curl there was a problem
        }

        mem->memory = ptr;
        memcpy(&(mem->memory[mem->size]), contents, realsize); //add new content to buffer
        mem->size += realsize;
        mem->memory[mem->size] = 0; //not needed since we'll be handling data as binary and not printable characters or strings

    }
    //always return the size sent even if it was a non 200 code so that we don't signal an error
    //see https://curl.haxx.se/libcurl/c/CURLOPT_WRITEFUNCTION.html
    return realsize;

}
