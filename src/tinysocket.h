#ifndef TINYSOCKET_H
#define TINYSOCKET_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <map>
#include <queue>

#include <node.h>
#include <node_buffer.h>
#include <node_object_wrap.h>
#include "http_parser.h"
#include "uv.h"

// size of work buffer for reading. this should be user configurable and be same size as in buffer
// TODO: need to figure out what is correct for this
#define READ_BUFFER 4096
#define MAX_CONTEXTS 4096

namespace tokamak {

// used by http parser
enum header_element_type { NONE = 0, FIELD, VALUE };
enum socket_type { TCP = 0, UNIX };
enum socket_mode { SOCKETS = 0, HTTP };

// write request struct
typedef struct {
  uv_write_t req; // libu write handle
  uv_buf_t buf; // buffer reference
  uint32_t fd; // id of the context
} write_req_t;

// object for passing socket server structure to libuv
typedef struct {
	void* object;
	void* callback;
} baton_t;

// struct of flags for JS callbacks set or not
typedef struct {
  uint8_t onConnect;
  uint8_t onHeaders;
  uint8_t onBody;
  uint8_t onRequest;
  uint8_t onResponse;
  uint8_t onClose;
  uint8_t onWrite;
  uint8_t onData;
  uint8_t onError;
} callbacks_t;
typedef struct _context _context;

// typedefs for http parser callbacks
typedef int (*on_data) (_context*, const char *at, size_t len);
typedef int (*cb) (_context*);

// context operations
void context_init (uv_stream_t* handle, _context* ctx);
void context_free (uv_handle_t* handle);

// socket callback signatures
void on_connection(uv_stream_t* server, int status);
void after_read(uv_stream_t* handle, ssize_t nread, const uv_buf_t* buf);
void after_write(uv_write_t* req, int status);
void after_write2(uv_write_t* req, int status);
void on_close(uv_handle_t* peer);
void after_shutdown(uv_shutdown_t* req, int status);
void echo_alloc(uv_handle_t* handle, size_t size, uv_buf_t* buf);

// http parser callback signatures
int message_begin_cb(http_parser *p);
int url_cb(http_parser *p, const char *buf, size_t len);
int header_field_cb(http_parser *p, const char *buf, size_t len);
int header_value_cb(http_parser *p, const char *buf, size_t len);
int body_cb(http_parser *p, const char *buf, size_t len);
int headers_complete_cb(http_parser *p);
int message_complete_cb(http_parser *p);

// http request
struct _request {
  uint8_t headerCount; // no. of http headers
  uint8_t maxHeaders; // maximum number of headers
  uint8_t setHeaders; // should we copy the headers to js structures or not
  uint16_t fieldlen; // length of current parser field
  uint32_t fieldlenp; // pointer in buffer to current chunk of parser field
  uint32_t urllength; // length of http url
  char *key; // holds current header key
  char *val; // holds current header value
  header_element_type lastel; // flag for http parser
};

// socket context
struct _context {
  uint32_t fd; // id of the context
  uint32_t readBufferLength; // size of read buffer
  uint32_t writeBufferLength; // size of write buffer
  uint32_t index; // position in buffer
  uv_buf_t in; // buffer for reading from socket
  uv_buf_t out; // buffer for writing to socket
  uv_buf_t buf; // work buffer
  uv_stream_t* handle; // stream handle
  void* data; // associated object
  http_parser *parser; // http parser instance
  _request* request; // request structure
  _context* proxyContext;
  int proxy;
  uint8_t cmode;
  uint8_t lastByte;
};

static http_parser_settings settings; // global settings for http parser
static std::queue<_context*> contexts; // queue for managing pool of contexts

class Socket : public node::ObjectWrap {
 public:
  // initialisation
  static void Init(v8::Isolate* isolate);
  static void NewInstance(const v8::FunctionCallbackInfo<v8::Value>& args);

  // persistent pointers to JS callbacks
  v8::Persistent<v8::Function> _onConnect;
  v8::Persistent<v8::Function> _onHeaders;
  v8::Persistent<v8::Function> _onBody;
  v8::Persistent<v8::Function> _onRequest;
  v8::Persistent<v8::Function> _onResponse;
  v8::Persistent<v8::Function> _onClose;
  v8::Persistent<v8::Function> _onWrite;
  v8::Persistent<v8::Function> _onData;
  v8::Persistent<v8::Function> _onError;
  v8::Persistent<v8::Array> headers[MAX_CONTEXTS];

  socket_mode mode = SOCKETS; // 0 = regular socket, 1 = HTTP socket 
  socket_type socktype = TCP; // 0 = tcp socket, 1 = Unix Domain Socket/Named Pipe
  callbacks_t callbacks; // pointers to JS callbacks
  uv_stream_t* _stream;

 private:

  Socket() {
    settings.on_message_begin = message_begin_cb;
    settings.on_header_field = header_field_cb;
    settings.on_header_value = header_value_cb;
    settings.on_url = url_cb;
    settings.on_body = body_cb;
    settings.on_headers_complete = headers_complete_cb;
    settings.on_message_complete = message_complete_cb;
  }

  ~Socket() {

  }

  //Socket Contructor
  static void New(const v8::FunctionCallbackInfo<v8::Value>& args); // Socket constuctor

  //Socket Instance Methods
  static void Setup(const v8::FunctionCallbackInfo<v8::Value>& args); // confiure socket buffers/options
  static void Bind(const v8::FunctionCallbackInfo<v8::Value>& args); // bind a socket to a port/path
  static void Connect(const v8::FunctionCallbackInfo<v8::Value>& args); // listen to port/path/handle
  static void Listen(const v8::FunctionCallbackInfo<v8::Value>& args); // listen to port/path/handle
  static void Close(const v8::FunctionCallbackInfo<v8::Value>& args); // close a socket
  static void Pull(const v8::FunctionCallbackInfo<v8::Value>& args); // take a string slice from the in buffer
  static void Push(const v8::FunctionCallbackInfo<v8::Value>& args); // push a string onto the out buffer
  static void Write(const v8::FunctionCallbackInfo<v8::Value>& args); // write from out buffer to the socket
  static void WriteText(const v8::FunctionCallbackInfo<v8::Value>& args); // write a v8 string to the socket
  static void Pause(const v8::FunctionCallbackInfo<v8::Value>& args); // pause the socket
  static void Resume(const v8::FunctionCallbackInfo<v8::Value>& args); // resume the socket
  static void Proxy(const v8::FunctionCallbackInfo<v8::Value>& args); // 1-1 socket proxy with another socket

  // TCP only methods
  static void RemoteAddress(const v8::FunctionCallbackInfo<v8::Value>& args); // remote ip4 address as string
  static void SetNoDelay(const v8::FunctionCallbackInfo<v8::Value>& args); // disable nagle on tcp socket
  static void SetKeepAlive(const v8::FunctionCallbackInfo<v8::Value>& args); // turn tcp keepalive on or off

  // JS Callbacks
  //static void onConnect(v8::Local<v8::String> property, const v8::PropertyCallbackInfo<v8::Value>& info);
  static void onConnect(const v8::FunctionCallbackInfo<v8::Value>& args); // resume the socket
  static void onError(const v8::FunctionCallbackInfo<v8::Value>& args); // resume the socket
  static void onData(const v8::FunctionCallbackInfo<v8::Value>& args); // resume the socket
  static void onWrite(const v8::FunctionCallbackInfo<v8::Value>& args); // resume the socket
  static void onClose(const v8::FunctionCallbackInfo<v8::Value>& args); // resume the socket
  static void onHeaders(const v8::FunctionCallbackInfo<v8::Value>& args); // resume the socket
  static void onBody(const v8::FunctionCallbackInfo<v8::Value>& args); // resume the socket
  static void onRequest(const v8::FunctionCallbackInfo<v8::Value>& args); // resume the socket
  static void onResponse(const v8::FunctionCallbackInfo<v8::Value>& args); // resume the socket

  // persistent reference to JS Socket constructor
  static v8::Persistent<v8::Function> constructor;

};

}

#endif