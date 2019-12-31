#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <winsock2.h>
#include <windows.h>
#include <assert.h>
#include <curl/curl.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include "openvpn/openvpn-plugin.h"
#include "openvpn/openvpn-vsocket.h"
#include "shapeshifter-meekheavy.h"







//CURL *curl;
//CURLcode res;
//
//struct MemoryStruct { //define structure
//    char *memory;
//    size_t size;
//};
//
//struct MemoryStruct chunk; // = malloc(sizeof(MemoryStruct)); //create instance of structure to store return data
//struct MemoryStruct dataToSend;
//struct MemoryStruct dataReceived;
//
//
//int main() {
//    dataToSend.memory = malloc(15);
//    dataToSend.size = 15;
//
//    dataReceived.memory = malloc(65536);
//    dataReceived.size = 65536;
//
//    dataToSend.memory = "data data data";
//
//    uint8_t initResult = 0;
//    uint8_t writeResult = 0;
//    uint32_t readResult = 0;
//    uint8_t closeResult = 0;
//
//    char *URL = "https://only.esni.defo.ie";
//    char *serverESNI = "only.esni.defo.ie";
//    char *coverESNI = "cover.defo.ie";
//    char *keyESNI = "/wElACniACQAHQAg5+fW92VqGCbFBrPYbbB8is00bfpVL0aUNAObapQg/z0AAhMBAQQAAAAAXgpnqQAAAABeCnzBAAA=";
//
//    //uint8_t initESNI(char *URL, char *serverESNI, char *coverESNI, char *keyESNI )
//    initResult = initESNI(URL,serverESNI,coverESNI,keyESNI);
//    printf(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> Init Result: %i\n", initResult);
//
//    //uint8_t writeESNI(char *data, size_t *len)
//    writeResult = writeESNI(dataToSend.memory, (size_t *) dataToSend.size);
//    printf(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> Write Result: %i\n", writeResult);
//
//    //uint32_t readESNI(char *returnBuffer, const size_t *requestedSize)
//    readResult = readESNI(dataReceived.memory, dataReceived.size);
//    printf(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> Read Result: %i\n", readResult);
//    printf("<><><><> data received <><><><>\n%s", dataReceived.memory);
//
//    //uint8_t closeESNI()
//    closeResult = closeESNI();
//    printf(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> Close Result: %i\n", closeResult);
//
//
//}
//
//
//uint8_t initESNI(char *URL, char *serverESNI, char *coverESNI, char *keyESNI )
//{
//    //setup esni connection, pass vars to function, return 0 on success 1 on fail
//
//    chunk.memory = malloc(1);  /* will be grown as needed by the realloc  in curlWriteFunction*/
//    //chunk.size = malloc(sizeof(size_t));    /* no data at this point */
//    chunk.size = 0;
//
//    curl_global_init(CURL_GLOBAL_DEFAULT);
//
//    curl = curl_easy_init();
//    if (curl) {
//        //curl_easy_setopt();
//
//        curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
//        curl_easy_setopt(curl, CURLOPT_IPRESOLVE, CURL_IPRESOLVE_V4); //force ipv4, ipv6 seems to not work on test server 2019.12.18
//        curl_easy_setopt(curl, CURLOPT_URL, URL);
//        curl_easy_setopt(curl, CURLOPT_ESNI_STATUS, CURLESNI_ENABLE | CURLESNI_STRICT);
//        curl_easy_setopt(curl, CURLOPT_ESNI_SERVER, serverESNI);
//        curl_easy_setopt(curl, CURLOPT_ESNI_COVER, coverESNI);
//        curl_easy_setopt(curl, CURLOPT_ESNI_ASCIIRR,keyESNI);
//        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *) &chunk);
//        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, &curlWriteFunction);
//        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, -1L);
//
//        char *sessionID = (char *) malloc((16 * 2) + 1);
//
//        int resultCode = sessionIDgen(sessionID);
//
//        if (resultCode == 0) {
//            //string2hexString(randomBuffer, hexRandomBuffer, 64);
//            printf("SessionID: %s\n", sessionID);
//
//            //return 0;
//        } else {
//            printf("Not enough random bytes for PRNG");
//            return 1;
//        }
//        char sessionIDheader[(16 * 2) + 1 + 14] = "X-Session-Id: ";
//        strcat(sessionIDheader, sessionID);
//        printf("sessionheader::  %s\n", sessionIDheader);
//        struct curl_slist *list = NULL;
//        list = curl_slist_append(list, "User-Agent: ");
//        list = curl_slist_append(list, sessionIDheader);
//        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, list);
//
//#ifdef SKIP_PEER_VERIFICATION
//        /*
//             * If you want to connect to a site who isn't using a certificate that is
//             * signed by one of the certs in the CA bundle you have, you can skip the
//             * verification of the server's certificate. This makes the connection
//             * A LOT LESS SECURE.
//             *
//             * If you have a CA cert for the server stored someplace else than in the
//             * default bundle, then the CURLOPT_CAPATH option might come handy for
//             * you.
//             */
//            curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
//#endif
//
//#ifdef SKIP_HOSTNAME_VERIFICATION
//        /*
//             * If the site you're connecting to uses a different host name that what
//             * they have mentioned in their server certificate's commonName (or
//             * subjectAltName) fields, libcurl will refuse to connect. You can skip
//             * this check, but this will make the connection less secure.
//             */
//            curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
//#endif
//
//
//        return 0;
//    }
//    return 1;
//
//}
//
//
//uint8_t writeESNI(char *data, size_t *len)
//{
//    //perform the ESNI connection, send data and receive response into buffer
//    //if response code is not 200, don't buffer the data
//    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, "data data data meh");
//
//    long httpResponseCode = 0;
//    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &httpResponseCode);
//
//    /* Perform the request, res will get the return code */
//    res = curl_easy_perform(curl);
//    /* Check for errors */
//    if(res != CURLE_OK) {
//        fprintf(stderr, "curl_easy_perform() failed: %s\n",
//                curl_easy_strerror(res));
//    }else{
//        printf("----THE_RESULTS----\n");
//        if (httpResponseCode != 200L){
//            //clear buffered data in struct chunk.memory
//        }
//        printf("%lu bytes retrieved\n", (unsigned long)chunk.size);
//        printf("PageData: \n%s", (char*)chunk.memory);
//    }
//
//
//}
//
//
//uint32_t readESNI(char *returnBuffer,  size_t requestedSize)
//{
//    //copy requested number of bytes of data from our buffer up to our buffer size, into the passed buffer,
//    // and then clear the returned data from our buffer
//    //return the number of bytes we actually copied into the returnBuffer
//    size_t bytesCopied = 0;
//
//    if (chunk.size <= requestedSize) {
//        //requested the same or more bytes than we have so copy it all
//        bytesCopied = chunk.size;
//        memcpy(returnBuffer, chunk.memory, chunk.size);
//
//        //manage our buffer
//        //we copied the whole buffer, so just clear it
//        chunk.memory = realloc(chunk.memory, 1);
//        chunk.memory = "\0"; //only handy for debug printing
//        chunk.size = 0UL;    /* no data at this point */
//    }
//
//    if (chunk.size > requestedSize){
//        //requested less than we have so only send back what they want
//        bytesCopied = requestedSize;
//        memcpy(returnBuffer, chunk.memory, requestedSize);
//
//        //manage our buffer
//        //we only returned part of our buffer so remove the part that was returned
//        memmove(chunk.memory, &chunk.memory[requestedSize], (chunk.size - requestedSize));
//        chunk.size = chunk.size - requestedSize;
//    }
//
//    return bytesCopied;
//
//}
//
//
//uint8_t closeESNI()
//{
//    //close connections and free memory
//
//    /* always cleanup after yourself */
//    //free(chunk.memory); chunk != NULL &&
//
//    if( chunk.memory != NULL) {
//        printf("not null");
//        free(chunk.memory);
//    }
//
//    curl_easy_cleanup(curl);
//    curl_global_cleanup();
//
//    return 0;
//}
//
//
//size_t curlWriteFunction(void *contents, size_t size, size_t nmemb, void *userp)
//{
//    long httpResponseCode = 0;
//    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &httpResponseCode);
//    size_t realsize = size * nmemb;
//    if (httpResponseCode == 200L) { //only copy data into buffer if the http result code is ok (200)
//
//        //we will add the data to the buffer, not overwrite
//        struct MemoryStruct *mem = (struct MemoryStruct *) userp; //recast *mem to access user structure since it was passed as a void
//
//        char *ptr = realloc(mem->memory, mem->size + realsize + 1); //resize and copy existing buffer into a newone with more space to handle new data
//        if (ptr == NULL) {
//            /* out of memory! */
//            printf("not enough memory (realloc returned NULL)\n");
//            return 0; //tell curl there was a problem
//        }
//
//        mem->memory = ptr;
//        memcpy(&(mem->memory[mem->size]), contents, realsize); //add new content to buffer
//        mem->size += realsize;
//        mem->memory[mem->size] = 0; //not needed since we'll be handling data as binary and not printable characters or strings
//
//    }
//    //always return the size sent even if it was a non 200 code so that we don't signal an error
//    //see https://curl.haxx.se/libcurl/c/CURLOPT_WRITEFUNCTION.html
//    return realsize;
//
//}


void string2hexString(uint8_t *input, char *output, uint8_t length)
{
    int loop;
    int i;

    i=0;
    loop=0;

    while(loop < length)
    {
        sprintf((char*)(output+i),"%02X", input[loop]);
        loop+=1;
        i+=2;
    }

    //insert NULL at the end of the output string
    output[i++] = '\0';
}

int sessionIDgen(char *sessionID)
{
    uint8_t *rnd = (uint8_t *)malloc(64 );

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);

    int resultCode = RAND_bytes(rnd,64); //fil rnd with 64 random bytes

    if (resultCode == 1){ //1=successful random number gen
        //successful rng
        SHA256_Update(&sha256, rnd, 64); //add rnd value to the message to be hashed
        SHA256_Final(hash, &sha256); //sha256hash the message and store in hash
        string2hexString(hash, sessionID, 16); //convert bytes to string and store in the var passed to func
        free(rnd);
        return 0; //success rng
    }else{
        free(rnd);
        return 1; //fail rng
    }

}


static inline bool is_invalid_handle(HANDLE h)
{
    return h == NULL || h == INVALID_HANDLE_VALUE;
}

struct shapeshifter_meeklite_socket_win32
{
    struct openvpn_vsocket_handle handle;
    struct shapeshifter_meeklite_context *ctx;

    /* Write is ready when idle; read is not-ready when idle. Both level-triggered. */
    struct openvpn_vsocket_win32_event_pair completion_events;
    unsigned last_rwflags;

    int client_id;
};

struct openvpn_vsocket_vtab shapeshifter_meeklite_socket_vtab;

static void free_socket(struct shapeshifter_meeklite_socket_win32 *sock)
{
    if (!sock)
        return;

    if (!is_invalid_handle(sock->completion_events.read)) {
        CloseHandle(sock->completion_events.read);
    }

    if (!is_invalid_handle(sock->completion_events.write)){
        CloseHandle(sock->completion_events.write);
    }

//    MeekliteCloseConnection(sock->client_id);

    free(sock);
}

static openvpn_vsocket_handle_t shapeshifter_meeklite_win32_bind(void *plugin_handle, const struct sockaddr *addr, openvpn_vsocket_socklen_t len)
{
    struct shapeshifter_meeklite_socket_win32 *sock = NULL;

    sock = calloc(1, sizeof(struct shapeshifter_meeklite_socket_win32));
    if (!sock)
        goto error;

    sock->handle.vtab = &shapeshifter_meeklite_socket_vtab;
    sock->ctx = (struct shapeshifter_meeklite_context *) plugin_handle;

    // Create an meeklite client.
//    sock->client_id = MeekliteInitializeClient(sock->ctx->url, sock->ctx->front);

    /* See above: write is ready when idle, read is not-ready when idle. */
    sock->completion_events.read = CreateEvent(NULL, TRUE, FALSE, NULL);
    sock->completion_events.write = CreateEvent(NULL, TRUE, TRUE, NULL);

    if (is_invalid_handle(sock->completion_events.read) || is_invalid_handle(sock->completion_events.write))
        goto error;

    struct sockaddr_in *addr_in = (struct sockaddr_in *)addr;
//    GoInt dial_result = MeekliteDial(sock->client_id, inet_ntoa(addr_in->sin_addr));
//
//    if (dial_result != 0)
//        goto error;

    return &sock->handle;

    error:
    shapeshifter_meeklite_log((struct shapeshifter_meeklite_context *) plugin_handle, PLOG_ERR,
                              "bind failure: WSA error = %d", WSAGetLastError());
    free_socket(sock);
    return NULL;
}

static void shapeshifter_meeklite_win32_request_event(openvpn_vsocket_handle_t handle, openvpn_vsocket_event_set_handle_t event_set, unsigned rwflags)
{
    struct shapeshifter_meeklite_socket_win32 *sock = (struct shapeshifter_meeklite_socket_win32 *)handle;
    shapeshifter_meeklite_log(((struct shapeshifter_meeklite_socket_win32 *)handle)->ctx, PLOG_DEBUG, "request-event: %d", rwflags);
    ((struct shapeshifter_meeklite_socket_win32 *)handle)->last_rwflags = 0;

    if (rwflags) {
        event_set->vtab->set_event(event_set, &sock->completion_events, rwflags,
                                   handle);
    }
}

static bool shapeshifter_meeklite_win32_update_event(openvpn_vsocket_handle_t handle, void *arg, unsigned rwflags)
{
    shapeshifter_meeklite_log(((struct shapeshifter_meeklite_socket_win32 *) handle)->ctx, PLOG_DEBUG,
                              "update-event: %p, %p, %d", handle, arg, rwflags);
    if (arg != handle) {
        return false;
    }

    ((struct shapeshifter_meeklite_socket_win32 *) handle)->last_rwflags |= rwflags;
    return true;
}

static unsigned shapeshifter_meeklite_win32_pump(openvpn_vsocket_handle_t handle)
{
    struct shapeshifter_meeklite_socket_win32 *sock = (struct shapeshifter_meeklite_socket_win32 *)handle;
    unsigned result = 0;

    if ((sock->last_rwflags & OPENVPN_VSOCKET_EVENT_READ)) {
        result |= OPENVPN_VSOCKET_EVENT_READ;
    }

    if ((sock->last_rwflags & OPENVPN_VSOCKET_EVENT_WRITE)) {
        result |= OPENVPN_VSOCKET_EVENT_WRITE;
    }

    shapeshifter_meeklite_log(sock->ctx, PLOG_DEBUG, "pump -> %d", result);

    return result;
}

static ssize_t shapeshifter_meeklite_win32_recvfrom(openvpn_vsocket_handle_t handle, void *buf, size_t len, struct sockaddr *addr, openvpn_vsocket_socklen_t *addrlen)
{
    struct shapeshifter_meeklite_socket_win32 *sock = (struct shapeshifter_meeklite_socket_win32 *)handle;
    int client_id = sock->client_id;
//    GoInt number_of_bytes_read = MeekliteRead(client_id, (void *)buf, (int)len);
//
//    if (number_of_bytes_read < 0)
//    {
//        return -1;
//    }

    ResetEvent(sock->completion_events.read);

//    return number_of_bytes_read;
    return -1;
}

static ssize_t shapeshifter_meeklite_win32_sendto(openvpn_vsocket_handle_t handle, const void *buf, size_t len, const struct sockaddr *addr, openvpn_vsocket_socklen_t addrlen)
{
    struct shapeshifter_meeklite_socket_win32 *sock = (struct shapeshifter_meeklite_socket_win32 *)handle;
    int client_id = sock->client_id;
//    GoInt number_of_characters_sent = MeekliteWrite(client_id, (void *)buf, (int)len);
//
//    if (number_of_characters_sent < 0)
//    {
//        goto error;
//    }

    SetEvent(sock->completion_events.write);

//    shapeshifter_meeklite_log(((struct shapeshifter_meeklite_socket_win32 *) handle)->ctx, PLOG_DEBUG, "sendto(%d) -> %d", (int)len, (int)number_of_characters_sent);

    //    return number_of_characters_sent;
    return -1;

    error:
    return -1;
}

static void shapeshifter_meeklite_win32_close(openvpn_vsocket_handle_t handle)
{
    free_socket((struct shapeshifter_meeklite_socket_win32 *) handle);
}

void
shapeshifter_meeklite_initialize_socket_vtab(void)
{
    shapeshifter_meeklite_socket_vtab.bind = shapeshifter_meeklite_win32_bind;
    shapeshifter_meeklite_socket_vtab.request_event = shapeshifter_meeklite_win32_request_event;
    shapeshifter_meeklite_socket_vtab.update_event = shapeshifter_meeklite_win32_update_event;
    shapeshifter_meeklite_socket_vtab.pump = shapeshifter_meeklite_win32_pump;
    shapeshifter_meeklite_socket_vtab.recvfrom = shapeshifter_meeklite_win32_recvfrom;
    shapeshifter_meeklite_socket_vtab.sendto = shapeshifter_meeklite_win32_sendto;
    shapeshifter_meeklite_socket_vtab.close = shapeshifter_meeklite_win32_close;
}





struct openvpn_vsocket_vtab shapeshifter_meeklite_socket_vtab = { NULL };

static void
free_context(struct shapeshifter_meeklite_context *context)
{
    if (!context)
        return;
    free(context);
}

void
shapeshifter_meeklite_log(struct shapeshifter_meeklite_context *ctx, openvpn_plugin_log_flags_t flags, const char *fmt, ...)
{
    va_list va;
    va_start(va, fmt);
    ctx->global_vtab->plugin_vlog(flags, shapeshifter_meeklite_PLUGIN_NAME, fmt, va);
    va_end(va);
}

// OpenVPN Plugin API

OPENVPN_EXPORT int openvpn_plugin_open_v3(int version, struct openvpn_plugin_args_open_in const *args, struct openvpn_plugin_args_open_return *out)
{
    struct shapeshifter_meeklite_context *context;
    context = (struct shapeshifter_meeklite_context *) calloc(1, sizeof(struct shapeshifter_meeklite_context));
    context->url = (char *)args->argv[1];
    context->front = (char *)args->argv[2];
    
    if (!context)
        return OPENVPN_PLUGIN_FUNC_ERROR;

    context->global_vtab = args->callbacks;
    
    // Sets up the VTable, useful stuff
    shapeshifter_meeklite_initialize_socket_vtab();

    // Tells openVPN what events we want the plugin to handle
    out->type_mask = OPENVPN_PLUGIN_MASK(OPENVPN_PLUGIN_SOCKET_INTERCEPT);
    
    // Gives OpenVPN the handle object to save and later give back to us in other calls
    out->handle = (openvpn_plugin_handle_t *) context;
    
    return OPENVPN_PLUGIN_FUNC_SUCCESS;
}

OPENVPN_EXPORT void
openvpn_plugin_close_v1(openvpn_plugin_handle_t handle)
{
    free_context((struct shapeshifter_meeklite_context *) handle);
}

OPENVPN_EXPORT int
openvpn_plugin_func_v3(int version,
                       struct openvpn_plugin_args_func_in const *arguments,
                       struct openvpn_plugin_args_func_return *retptr)
{
    /* We don't ask for any bits that use this interface. */
    return OPENVPN_PLUGIN_FUNC_ERROR;
}

// Provides OpenVPN with the VTable
// Functions on the VTable are called when there are network events
OPENVPN_EXPORT void *
openvpn_plugin_get_vtab_v1(int selector, size_t *size_out)
{
    switch (selector)
    {
        case OPENVPN_VTAB_SOCKET_INTERCEPT_SOCKET_V1:
            if (shapeshifter_meeklite_socket_vtab.bind == NULL)
                return NULL;
            *size_out = sizeof(struct openvpn_vsocket_vtab);
            return &shapeshifter_meeklite_socket_vtab;

        default:
            return NULL;
    }
}
