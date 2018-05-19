#include <node.h>
#include "tinysocket.h"

namespace tokamak {

  using v8::Context;
  using v8::Function;
  using v8::FunctionCallbackInfo;
  using v8::FunctionTemplate;
  using v8::Isolate;
  using v8::Local;
  using v8::Number;
  using v8::Integer;
  using v8::Object;
  using v8::Persistent;
  using v8::String;
  using v8::Value;
  using v8::Array;

  Persistent<Function> Socket::constructor;
  static int contextid = 0; // incrementing counter for context ids
  static _context* contextMap[MAX_CONTEXTS];

  _context* context_init(uv_stream_t* handle, Socket* s, uint8_t cmode) {
    Isolate * isolate = Isolate::GetCurrent();
    v8::HandleScope handleScope(isolate);
    _context* ctx;
    if(contexts.empty()) {
      ctx = (_context*)calloc(sizeof(_context), 1);
      ctx->fd = contextid++;
      if(s->mode == HTTP) {
        ctx->request = (_request*)calloc(sizeof(_request), 1);
        ctx->parser = (http_parser *)calloc(sizeof(http_parser), 1);
        ctx->parser->data = ctx;
        ctx->buf = uv_buf_init((char *)calloc(READ_BUFFER, 1), READ_BUFFER);
      }
      contextMap[ctx->fd] = ctx;
    }
    else {
      ctx = contexts.front();
      contexts.pop();
    }
    ctx->proxy = 0;
    ctx->cmode = cmode;
    if(s->mode == HTTP) {
      ctx->request->setHeaders = 0;
      http_parser_init(ctx->parser, HTTP_REQUEST);
    }
    ctx->handle = handle;
    handle->data = ctx;
    return ctx;
  }

  void context_free(uv_handle_t* handle) {
    _context* context = (_context*)handle->data;
    contexts.push(context);
    free(handle);
  }

  int message_begin_cb(http_parser *p) {
    _context *ctx = (_context *)p->data;
    ctx->request->headerCount = 0;
    ctx->request->urllength = 0;
    uint8_t *rr = (uint8_t *)ctx->in.base + 8;
    rr[0] = 0;
    rr[1] = 0;
    rr[2] = 0;
    rr[3] = 0;
    ctx->request->lastel = NONE;
    ctx->index = 12;
    ctx->request->fieldlen = 0;
    return 0;
  }

  int url_cb(http_parser *p, const char *buf, size_t len) {
    _context *ctx = (_context *)p->data;
    if(ctx->index + len > ctx->readBufferLength) {
      return -1;
    }
    uint8_t *rr = (uint8_t *)ctx->in.base + ctx->index;
    memcpy(rr, buf, len);
    ctx->index += len;
    ctx->request->urllength += len;
    ctx->request->fieldlenp = ctx->index;
    return 0;
  }

  int header_field_cb(http_parser *p, const char *buf, size_t len) {
    _context *ctx = (_context *)p->data;
    if (ctx->request->lastel != FIELD) {
      // new field
      if(ctx->index + len + 2 > ctx->readBufferLength) {
        return -1;
      }
      //TODO: check for max headers
      ctx->request->headerCount++;
      uint8_t* rr = (uint8_t *)ctx->in.base + ctx->index;
      ctx->request->fieldlen = len;
      ctx->request->fieldlenp = ctx->index;
      rr[0] = 0xff & (len >> 8);
      rr[1] = 0xff & len;
      rr = (uint8_t *)ctx->in.base + ctx->index + 2;
      //TODO: buffer overrun - check for end of headers buffer
      ctx->request->key = (char *)rr;
      memcpy(rr, buf, len);
      ctx->index += (len + 2);
    }
    else {
      // existing field
      if(ctx->index + len > ctx->readBufferLength) {
        return -1;
      }
      ctx->request->fieldlen += len;
      uint8_t* rr = (uint8_t *)ctx->in.base + ctx->request->fieldlenp;
      rr[0] = 0xff & (ctx->request->fieldlen >> 8);
      rr[1] = 0xff & ctx->request->fieldlen;
      rr = (uint8_t *)ctx->in.base + ctx->index;
      //TODO: buffer overrun - check for end of headers buffer
      memcpy(rr, buf, len);
      ctx->index += len;
    }
    ctx->request->lastel = FIELD;
    return 0;
  }

  int header_value_cb(http_parser *p, const char *buf, size_t len) {
    _context *ctx = (_context *)p->data;
    if (ctx->request->lastel != VALUE) {
      // new field
      if(ctx->index + len + 2 > ctx->readBufferLength) {
        return -1;
      }
      uint8_t* rr = (uint8_t *)ctx->in.base + ctx->index;
      ctx->request->fieldlen = len;
      ctx->request->fieldlenp = ctx->index;
      rr[0] = 0xff & (len >> 8);
      rr[1] = 0xff & len;
      rr = (uint8_t *)ctx->in.base + ctx->index + 2;
      ctx->request->val = (char *)rr;
      //TODO: buffer overrun - check for end of headers buffer
      memcpy(rr, buf, len);
      ctx->index += (len + 2);
    }
    else {
      // existing field
      if(ctx->index + len > ctx->readBufferLength) {
        return -1;
      }
      ctx->request->fieldlen += len;
      uint8_t* rr = (uint8_t *)ctx->in.base + ctx->request->fieldlenp;
      rr[0] = 0xff & (ctx->request->fieldlen >> 8);
      rr[1] = 0xff & ctx->request->fieldlen;
      rr = (uint8_t *)ctx->in.base + ctx->index;
      //TODO: buffer overrun - check for end of headers buffer
      memcpy(rr, buf, len);
      ctx->index += len;
    }
    ctx->request->lastel = VALUE;
    return 0;
  }

  int body_cb(http_parser *p, const char *buf, size_t len) {
    if (len > 0) {
      Isolate * isolate = Isolate::GetCurrent();
      v8::HandleScope handleScope(isolate);
      _context *ctx = (_context *)p->data;
      if(len > ctx->readBufferLength) {
        return -1;
      }
      Socket* s = (Socket*)ctx->data;
      if(s->callbacks.onBody == 1) {
        uint8_t *rr = (uint8_t *)ctx->in.base;
        //TODO: buffer overrun - check for end of headers buffer
        memcpy(rr, buf, len);
        Local<Value> argv[2] = {Integer::New(isolate, ctx->fd), Integer::New(isolate, len)};
        Local<Function> onBody = Local<Function>::New(isolate, s->_onBody);
        onBody->Call(isolate->GetCurrentContext()->Global(), 2, argv);
      }
    }
    return 0;
  }

  int headers_complete_cb(http_parser *p) {
    Isolate * isolate = Isolate::GetCurrent();
    v8::HandleScope handleScope(isolate);
    _context *ctx = (_context *)p->data;
    Socket* s = (Socket*)ctx->data;
    uint8_t *rr = (uint8_t *)ctx->in.base;
    rr[0] = p->http_major;
    rr[1] = p->http_minor;
    rr[2] = ctx->request->headerCount;
    if (ctx->cmode == 0) {
      rr[3] = 0xff & (http_method)p->method;
      rr[4] = p->upgrade;
    } else {
      rr[3] = 0xff & (p->status_code >> 8);
      rr[4] = 0xff & p->status_code;
    }
    rr[5] = http_should_keep_alive(p);

    if(ctx->request->setHeaders) {
      Local<Array> array = Local<Array>::New(isolate, s->headers[ctx->fd]);
      uint8_t* data = (uint8_t*)ctx->in.base;
      uint8_t hc = data[2];
      uint8_t* bin = data + 12;
      uint8_t h = 0;
      uint16_t len = 0;
      //TODO: check for array length
      array->Set(h++, String::NewFromUtf8(isolate, (char*)bin, v8::String::kNormalString, ctx->request->urllength));
      bin += ctx->request->urllength;
      while(hc--) {
        Local<Array> ha = array->Get(h).As<Array>();
        len = (bin[0] << 8) + bin[1];
        bin += 2;
        ha->Set(0, String::NewFromUtf8(isolate, (char*)bin, v8::String::kNormalString, len));
        bin += len;
        len = (bin[0] << 8) + bin[1];
        bin += 2;
        ha->Set(1, String::NewFromUtf8(isolate, (char*)bin, v8::String::kNormalString, len));
        bin += len;
        h++;
      }
    } else {
      rr[8] = 0xff & (ctx->request->urllength >> 24);
      rr[9] = 0xff & (ctx->request->urllength >> 16);
      rr[10] = 0xff & (ctx->request->urllength >> 8);
      rr[11] = 0xff & ctx->request->urllength;
    }

    if(s->callbacks.onHeaders == 1) {
      Local<Value> argv[2] = {Integer::New(isolate, ctx->fd), Integer::New(isolate, ctx->index)};
      Local<Function> onHeaders = Local<Function>::New(isolate, s->_onHeaders);
      onHeaders->Call(isolate->GetCurrentContext()->Global(), 1, argv);
    }
    return 0;
  }

  int message_complete_cb(http_parser *p) {
    Isolate * isolate = Isolate::GetCurrent();
    v8::HandleScope handleScope(isolate);
    _context *ctx = (_context *)p->data;
    Socket* s = (Socket*)ctx->data;
    if(ctx->cmode == 0 && s->callbacks.onRequest == 1) {
      Local<Value> argv[1] = {Integer::New(isolate, ctx->fd)};
      Local<Function> onRequest = Local<Function>::New(isolate, s->_onRequest);
      onRequest->Call(isolate->GetCurrentContext()->Global(), 1, argv);
    }
    if(ctx->cmode == 1 && s->callbacks.onResponse == 1) {
      Local<Value> argv[1] = {Integer::New(isolate, ctx->fd)};
      Local<Function> onResponse = Local<Function>::New(isolate, s->_onResponse);
      onResponse->Call(isolate->GetCurrentContext()->Global(), 1, argv);
    }
    return 0;
  }

  void after_write(uv_write_t* req, int status) {
    Isolate * isolate = Isolate::GetCurrent();
    v8::HandleScope handleScope(isolate);
    write_req_t* wr = (write_req_t*) req;
    _context* ctx = contextMap[wr->fd];
    Socket* s = (Socket*)ctx->data;
    if(s->callbacks.onWrite == 1) {
      Local<Value> argv[4] = {Integer::New(isolate, ctx->fd),
                              Integer::New(isolate, wr->req.write_index),
                              Integer::New(isolate, status), Integer::New(isolate, wr->buf.len)};
      Local<Function> onWrite = Local<Function>::New(isolate, s->_onWrite);
      onWrite->Call(isolate->GetCurrentContext()->Global(), 4, argv);
    }
    free(wr);
  }

  void after_write2(uv_write_t* req, int status) {
    Isolate * isolate = Isolate::GetCurrent();
    v8::HandleScope handleScope(isolate);
    write_req_t* wr = (write_req_t*) req;
    _context* ctx = contextMap[wr->fd];
    Socket* s = (Socket*)ctx->data;
    if(s->callbacks.onWrite == 1) {
      Local<Value> argv[4] = {Integer::New(isolate, ctx->fd),
                              Integer::New(isolate, wr->req.write_index),
                              Integer::New(isolate, status), Integer::New(isolate, wr->buf.len)};
      Local<Function> onWrite = Local<Function>::New(isolate, s->_onWrite);
      onWrite->Call(isolate->GetCurrentContext()->Global(), 4, argv);
    }
    free(wr->buf.base);
    free(wr);
  }

  void on_close(uv_handle_t* peer) {
    Isolate * isolate = Isolate::GetCurrent();
    v8::HandleScope handleScope(isolate);
    _context* ctx = (_context*)peer->data;
    Socket* s = (Socket*)ctx->data;
    if(ctx->proxy == 1) {
      //if(uv_is_closing((uv_handle_t*)ctx->proxyContext->handle) == 0) {
      if(ctx->proxyContext->handle->type == UV_NAMED_PIPE || ctx->proxyContext->handle->type == UV_TCP) {
        uv_shutdown_t *req;
        req = (uv_shutdown_t *)malloc(sizeof *req);
        uv_shutdown(req, ctx->proxyContext->handle, after_shutdown);
      }
    }
    if(s->callbacks.onClose == 1) {
      Local<Value> argv[1] = { Integer::New(isolate, ctx->fd) };
      Local<Function> onClose = Local<Function>::New(isolate, s->_onClose);
      onClose->Call(isolate->GetCurrentContext()->Global(), 1, argv);
    }
    context_free(peer);
  }

  void on_close2(uv_handle_t* peer) {
    free(peer);
  }

  void after_shutdown(uv_shutdown_t* req, int status) {
    if(uv_is_closing((uv_handle_t*)req->handle) == 0) {
      //uv_close((uv_handle_t*)req->handle, on_close);
      free(req);
    }
  }

  void after_read(uv_stream_t* handle, ssize_t nread, const uv_buf_t* buf) {
    Isolate * isolate = Isolate::GetCurrent();
    v8::HandleScope handleScope(isolate);
    _context* ctx = (_context*)handle->data;
    Socket* s = (Socket*)ctx->data;
    if (nread == UV_EOF) {
      uv_close((uv_handle_t*)handle, on_close);
      return;
    }
    if (nread < 0) {
      if(s->callbacks.onError == 1) {
        Local<Value> argv[3] = { Integer::New(isolate, ctx->fd), Number::New(isolate, nread), String::NewFromUtf8(isolate, uv_strerror(nread), v8::String::kNormalString) };
        Local<Function> onError = Local<Function>::New(isolate, s->_onError);
        onError->Call(isolate->GetCurrentContext()->Global(), 3, argv);
      }
      uv_close((uv_handle_t*)handle, on_close);
      return;
    }
    if (nread == 0) {
      return;
    }
    ctx->lastByte = 0;
    if(s->mode == HTTP) {
      ssize_t np = http_parser_execute(ctx->parser, &settings, buf->base, nread);
      if(np != nread) {
        if (ctx->parser->http_errno == HPE_PAUSED) {
          uint8_t* lastByte = (uint8_t*)(buf->base + np);
          ctx->lastByte = *lastByte;
        } else {
          if(s->callbacks.onError == 1) {
            Local<Value> argv[3] = { Integer::New(isolate, ctx->fd), Number::New(isolate, ctx->parser->http_errno), String::NewFromUtf8(isolate, http_errno_description((http_errno)ctx->parser->http_errno), v8::String::kNormalString) };
            Local<Function> onError = Local<Function>::New(isolate, s->_onError);
            onError->Call(isolate->GetCurrentContext()->Global(), 3, argv);
          }
          uv_shutdown_t *req;
          req = (uv_shutdown_t *)malloc(sizeof *req);
          uv_shutdown(req, handle, after_shutdown);
        }
      }
    }
    else {
      if(ctx->proxy == 1) {
        write_req_t *wr;
        wr = (write_req_t *)malloc(sizeof *wr);
        char* wrb = (char*)calloc(nread, 1);
        memcpy(wrb, buf->base, nread);
        wr->buf = uv_buf_init(wrb, nread);
        //wr->buf = uv_buf_init(buf->base, nread);
        wr->fd = ctx->proxyContext->fd;
        int r = uv_write(&wr->req, ctx->proxyContext->handle, &wr->buf, 1, after_write2);
        // TODO: handle bad return code here
      }
      if(s->callbacks.onData == 1) {
        Local<Value> argv[2] = { Integer::New(isolate, ctx->fd), Number::New(isolate, nread) };
        Local<Function> onData = Local<Function>::New(isolate, s->_onData);
        onData->Call(isolate->GetCurrentContext()->Global(), 2, argv);
      }
    }
  }

  void echo_alloc(uv_handle_t* handle, size_t size, uv_buf_t* buf) {
    _context *ctx = (_context *)handle->data;
    Socket* s = (Socket*)ctx->data;
    if(s->mode == HTTP) {
      buf->base = ctx->buf.base;
      buf->len = ctx->readBufferLength;
    }
    else {
      buf->base = ctx->in.base;
      buf->len = ctx->readBufferLength;
    }
  }

  void on_client_connection(uv_connect_t *client, int status) {
    baton_t* baton = (baton_t*)client->data;
    cb foo = (cb)baton->callback;
    Socket* s = (Socket*)baton->object;
    _context *ctx = (_context *)client->handle->data;
    ctx->data = s;
    if (!uv_is_readable(client->handle) || !uv_is_writable(client->handle) ||
        uv_is_closing((uv_handle_t *)client->handle)) {
      return;
    }
    foo(ctx);
    status = uv_read_start(client->handle, echo_alloc, after_read);
    assert(status == 0);
  }

  void on_connection(uv_stream_t* server, int status) {
    baton_t* baton = (baton_t*)server->data;
    uv_stream_t* stream;
    cb foo = (cb)baton->callback;
    Socket* s = (Socket*)baton->object;
    if(s->socktype == TCP) {
      stream = (uv_stream_t*)malloc(sizeof(uv_tcp_t));
      status = uv_tcp_init(uv_default_loop(), (uv_tcp_t*)stream);
      status = uv_tcp_simultaneous_accepts((uv_tcp_t*) stream, 1);
    }
    else {
      stream = (uv_stream_t*)malloc(sizeof(uv_pipe_t));
      status = uv_pipe_init(uv_default_loop(), (uv_pipe_t*)stream, 0);
    }
    status = uv_accept(server, stream);
    _context* ctx = context_init(stream, s, 0);
    ctx->data = baton->object;
    foo(ctx);
    status = uv_read_start(stream, echo_alloc, after_read);
    assert(status == 0);
  }

  void Socket::Init(Isolate* isolate) {

    Local<FunctionTemplate> tpl = FunctionTemplate::New(isolate, New);

    tpl->SetClassName(String::NewFromUtf8(isolate, "Socket"));
    tpl->InstanceTemplate()->SetInternalFieldCount(1);

    NODE_SET_PROTOTYPE_METHOD(tpl, "listen", Listen);
    NODE_SET_PROTOTYPE_METHOD(tpl, "connect", Connect);
    NODE_SET_PROTOTYPE_METHOD(tpl, "bind", Bind);
    NODE_SET_PROTOTYPE_METHOD(tpl, "close", Close);
    NODE_SET_PROTOTYPE_METHOD(tpl, "pull", Pull);
    NODE_SET_PROTOTYPE_METHOD(tpl, "push", Push);
    NODE_SET_PROTOTYPE_METHOD(tpl, "write", Write);
    NODE_SET_PROTOTYPE_METHOD(tpl, "writeText", WriteText);
    NODE_SET_PROTOTYPE_METHOD(tpl, "setup", Setup);
    NODE_SET_PROTOTYPE_METHOD(tpl, "setNoDelay", SetNoDelay);
    NODE_SET_PROTOTYPE_METHOD(tpl, "pause", Pause);
    NODE_SET_PROTOTYPE_METHOD(tpl, "resume", Resume);
    NODE_SET_PROTOTYPE_METHOD(tpl, "setKeepAlive", SetKeepAlive);
    NODE_SET_PROTOTYPE_METHOD(tpl, "proxy", Proxy);
    NODE_SET_PROTOTYPE_METHOD(tpl, "remoteAddress", RemoteAddress);

    NODE_SET_PROTOTYPE_METHOD(tpl, "onConnect", onConnect);
    NODE_SET_PROTOTYPE_METHOD(tpl, "onHeaders", onHeaders);
    NODE_SET_PROTOTYPE_METHOD(tpl, "onBody", onBody);
    NODE_SET_PROTOTYPE_METHOD(tpl, "onRequest", onRequest);
    NODE_SET_PROTOTYPE_METHOD(tpl, "onResponse", onResponse);
    NODE_SET_PROTOTYPE_METHOD(tpl, "onClose", onClose);
    NODE_SET_PROTOTYPE_METHOD(tpl, "onWrite", onWrite);
    NODE_SET_PROTOTYPE_METHOD(tpl, "onData", onData);
    NODE_SET_PROTOTYPE_METHOD(tpl, "onError", onError);

    constructor.Reset(isolate, tpl->GetFunction());
  }

  void Socket::New(const FunctionCallbackInfo<Value>& args) {
    Isolate* isolate = args.GetIsolate();
    if (args.IsConstructCall()) {
      Socket* obj = new Socket();
      int len = args.Length();
      if(len > 0) {
        obj->mode = (socket_mode)args[0]->Int32Value();
      }
      if(len > 1) {
        obj->socktype = (socket_type)args[1]->Int32Value();
      }
      obj->Wrap(args.This());
      args.GetReturnValue().Set(args.This());
    } else {
      Local<Function> cons = Local<Function>::New(isolate, constructor);
      Local<Context> context = isolate->GetCurrentContext();
      Local<Object> instance = cons->NewInstance(context, 0, NULL).ToLocalChecked();
      args.GetReturnValue().Set(instance);
    }
  }

  void Socket::NewInstance(const FunctionCallbackInfo<Value>& args) {
    Isolate* isolate = args.GetIsolate();
    const unsigned argc = 2;
    Local<Value> argv[argc] = { args[0], args[1] };
    Local<Function> cons = Local<Function>::New(isolate, constructor);
    Local<Context> context = isolate->GetCurrentContext();
    Local<Object> instance = cons->NewInstance(context, argc, argv).ToLocalChecked();
    args.GetReturnValue().Set(instance);
  }

  void Socket::RemoteAddress(const FunctionCallbackInfo<Value>& args) {
    Isolate* isolate = args.GetIsolate();
    v8::HandleScope handleScope(isolate);
    Socket* s = ObjectWrap::Unwrap<Socket>(args.Holder());
    args.GetReturnValue().Set(String::NewFromUtf8(isolate, "", v8::String::kNormalString, 0));
    return;
    struct sockaddr_storage address;
    if(args.Length() > 0) {
      int fd = args[0]->Int32Value();
      _context* ctx = contextMap[fd];
      int addrlen = sizeof(address);
      int r = uv_tcp_getpeername((uv_tcp_t *)ctx->handle, reinterpret_cast<sockaddr *>(&address), &addrlen);
      if (r) {
        return;
      }
      const sockaddr *addr = reinterpret_cast<const sockaddr *>(&address);
      char ip[INET6_ADDRSTRLEN];
      const sockaddr_in *a4;
      a4 = reinterpret_cast<const sockaddr_in*>(addr);
      int len = sizeof ip;
      uv_inet_ntop(AF_INET, &a4->sin_addr, ip, len);
      args.GetReturnValue().Set(String::NewFromUtf8(isolate, ip, v8::String::kNormalString, len));
      return;
    }
  }

  void Socket::Close(const FunctionCallbackInfo<Value>& args) {
    Isolate* isolate = args.GetIsolate();
    v8::HandleScope handleScope(isolate);
    Socket* s = ObjectWrap::Unwrap<Socket>(args.Holder());
    int do_shutdown = 1;
    if(args.Length() > 0) {
      int fd = args[0]->Int32Value();
      _context* ctx = contextMap[fd];
      if(args.Length() > 0) {
        do_shutdown = args[1]->Int32Value();
      }
      if(do_shutdown) {
        uv_shutdown_t *req;
        req = (uv_shutdown_t *)malloc(sizeof *req);
        int r = uv_shutdown(req, ctx->handle, after_shutdown);
        args.GetReturnValue().Set(Integer::New(isolate, r));
      } else {
        uv_close((uv_handle_t*)ctx->handle, on_close);
      }
    } else if(s->_stream) {
      uv_close((uv_handle_t*)s->_stream, on_close2);
      args.GetReturnValue().Set(Integer::New(isolate, 0));
    }
  }

  int onNewConnection(_context* ctx) {
    Socket* obj = (Socket*)ctx->data;
    Isolate * isolate = Isolate::GetCurrent();
    v8::HandleScope handleScope(isolate);
    if(obj->callbacks.onConnect == 1) {
      const unsigned int argc = 1;
      Local<Value> argv[argc] = { Integer::New(isolate, ctx->fd) };
      Local<Function> foo = Local<Function>::New(isolate, obj->_onConnect);
      foo->Call(isolate->GetCurrentContext()->Global(), 1, argv);
    }
    return 0;
  }

  void Socket::Setup(const FunctionCallbackInfo<Value>& args) {
    Isolate* isolate = args.GetIsolate();
    Socket* s = ObjectWrap::Unwrap<Socket>(args.Holder());
    v8::HandleScope handleScope(isolate);
    int fd = args[0]->Int32Value();
    _context* ctx = contextMap[fd];
    size_t len = node::Buffer::Length(args[1]);
    ctx->in = uv_buf_init(node::Buffer::Data(args[1]), len);
    ctx->readBufferLength = len;
    len = node::Buffer::Length(args[2]);
    ctx->out = uv_buf_init(node::Buffer::Data(args[2]), len);
    if(args.Length() > 3) {
      s->headers[fd].Reset(isolate, args[3].As<Array>());
      ctx->request->setHeaders = 1;
    }
    args.GetReturnValue().Set(Integer::New(isolate, 0));
  }

  void Socket::Pull(const FunctionCallbackInfo<Value>& args) {
    Isolate* isolate = args.GetIsolate();
    int fd = args[0]->Int32Value();
    int32_t off = args[1]->Int32Value();
    int32_t len = args[2]->Int32Value();
    _context* ctx = contextMap[fd];
    char *data = ctx->in.base + off;
    args.GetReturnValue().Set(String::NewFromUtf8(isolate, data, v8::String::kNormalString, len));
  }

  void Socket::Push(const FunctionCallbackInfo<Value>& args) {
    Isolate* isolate = args.GetIsolate();
    int fd = args[0]->Int32Value();
    Local<String> str = args[1].As<String>();
    int length = str->Length();
    int off = args[2]->Int32Value();
    _context* ctx = contextMap[fd];
    char *src = ctx->out.base + off;
    int chars_written;
    int written = str->WriteUtf8(src, length, &chars_written, v8::String::HINT_MANY_WRITES_EXPECTED | v8::String::NO_NULL_TERMINATION);
    args.GetReturnValue().Set(Integer::New(isolate, written));
  }

  void Socket::WriteText(const FunctionCallbackInfo<Value>& args) {
    Isolate* isolate = args.GetIsolate();
    int fd = args[0]->Int32Value();
    _context* ctx = contextMap[fd];
    int off = args[1]->Int32Value();
    Local<String> str = args[2].As<String>();
    int len = str->Length();
    char *src = ctx->out.base + off;
    int chars_written;
    len = str->WriteUtf8(src, len, &chars_written, v8::String::HINT_MANY_WRITES_EXPECTED | v8::String::NO_NULL_TERMINATION);
    write_req_t *wr;
    wr = (write_req_t *)malloc(sizeof *wr);
    wr->buf = uv_buf_init(src, len);
    wr->fd = ctx->fd;
    if (ctx->handle == NULL) {
      args.GetReturnValue().Set(Integer::New(isolate, -1));
      return;
    }
    int r = uv_write(&wr->req, ctx->handle, &wr->buf, 1, after_write);
    args.GetReturnValue().Set(Integer::New(isolate, r));
  }

  void Socket::SetKeepAlive(const FunctionCallbackInfo<Value>& args) {
    Isolate* isolate = args.GetIsolate();
    int fd = args[0]->Int32Value();
    _context* ctx = contextMap[fd];
    int enable = static_cast<int>(args[1]->BooleanValue());
    unsigned int delay = args[2]->Uint32Value();
    int r = uv_tcp_keepalive((uv_tcp_t *)ctx->handle, enable, delay);
    args.GetReturnValue().Set(Integer::New(isolate, r));
  }

  void Socket::SetNoDelay(const FunctionCallbackInfo<Value>& args) {
    Isolate* isolate = args.GetIsolate();
    int fd = args[0]->Int32Value();
    _context* ctx = contextMap[fd];
    int enable = static_cast<int>(args[1]->BooleanValue());
    int r = uv_tcp_nodelay((uv_tcp_t *)ctx->handle, enable);
    args.GetReturnValue().Set(Integer::New(isolate, r));
  }

  void Socket::Pause(const FunctionCallbackInfo<Value>& args) {
    Isolate* isolate = args.GetIsolate();
    int fd = args[0]->Int32Value();
    _context* ctx = contextMap[fd];
    Socket* s = (Socket*)ctx->data;
    if(s->mode == HTTP) {
      http_parser_pause(ctx->parser, 1);
    }
    int r = uv_read_stop(ctx->handle);
    args.GetReturnValue().Set(Integer::New(isolate, r));
  }

  void Socket::Proxy(const FunctionCallbackInfo<Value>& args) {
    Isolate* isolate = args.GetIsolate();
    int fd = args[0]->Int32Value();
    int bfd = args[1]->Int32Value();
    _context* server = contextMap[fd];
    _context* backend = contextMap[bfd];
    server->proxy = 1;
    backend->proxy = 1;
    server->proxyContext = backend;
    backend->proxyContext = server;
    args.GetReturnValue().Set(Integer::New(isolate, 0));
  }

  void Socket::Resume(const FunctionCallbackInfo<Value>& args) {
    Isolate* isolate = args.GetIsolate();
    int fd = args[0]->Int32Value();
    _context* ctx = contextMap[fd];
    Socket* s = (Socket*)ctx->data;
    if(s->mode == HTTP) {
      http_parser_pause(ctx->parser, 0);
    }
    int r = uv_read_start(ctx->handle, echo_alloc, after_read);
    if(ctx->lastByte) {
      ssize_t np = http_parser_execute(ctx->parser, &settings, (const char*)&ctx->lastByte, 1);
    }
    args.GetReturnValue().Set(Integer::New(isolate, r));
  }

  void Socket::Write(const FunctionCallbackInfo<Value>& args) {
    Isolate* isolate = args.GetIsolate();
    int fd = args[0]->Int32Value();
    int off = args[1]->Int32Value();
    int len = args[2]->Int32Value();
    _context* ctx = contextMap[fd];
    write_req_t *wr;
    wr = (write_req_t *)malloc(sizeof *wr);
    char *src = ctx->out.base + off;
    wr->buf = uv_buf_init(src, len);
    wr->fd = ctx->fd;
    if (ctx->handle == NULL) {
      args.GetReturnValue().Set(Integer::New(isolate, -1));
      return;
    }
    int r = uv_write(&wr->req, ctx->handle, &wr->buf, 1, after_write);
    args.GetReturnValue().Set(Integer::New(isolate, r));
  }

  void Socket::Connect(const FunctionCallbackInfo<Value>& args) {
    Isolate* isolate = args.GetIsolate();
    Socket* s = ObjectWrap::Unwrap<Socket>(args.Holder());
    if (s->socktype == TCP) {
      v8::String::Utf8Value utf8Value(args[0]);
      char* ip_address = (*utf8Value);
      const unsigned int port = args[1]->IntegerValue();
      struct sockaddr_in address;
      int r = uv_ip4_addr(ip_address, port, &address);
      uv_tcp_t *sock = (uv_tcp_t *)malloc(sizeof(uv_tcp_t));
      sock->data = s;
      baton_t* baton = (baton_t*)malloc(sizeof(baton_t));
      baton->callback = (void*)onNewConnection;
      baton->object = s;
      sock->data = baton;
      r = uv_tcp_init(uv_default_loop(), sock);
      if (r) {
        args.GetReturnValue().Set(Integer::New(isolate, r));
        return;
      }
      uv_connect_t *cn_wrap = (uv_connect_t *)malloc(sizeof(uv_connect_t));
      cn_wrap->data = baton;
      r = uv_tcp_connect(cn_wrap, sock, (const struct sockaddr*) &address, on_client_connection);
      if (r) {
        free(cn_wrap);
        args.GetReturnValue().Set(Integer::New(isolate, r));
        return;
      }
      context_init((uv_stream_t *)sock, s, 1);
      args.GetReturnValue().Set(Integer::New(isolate, 0));
      return;
    } else {
      v8::String::Utf8Value utf8Value(args[0]);
      char* path = (*utf8Value);
      uv_pipe_t *sock = (uv_pipe_t *)malloc(sizeof(uv_pipe_t));
      sock->data = s;
      baton_t* baton = (baton_t*)malloc(sizeof(baton_t));
      baton->callback = (void*)onNewConnection;
      baton->object = s;
      sock->data = baton;
      int r = uv_pipe_init(uv_default_loop(), sock, 0);
      if (r) {
        args.GetReturnValue().Set(Integer::New(isolate, r));
        return;
      }
      uv_connect_t *cn_wrap = (uv_connect_t *)malloc(sizeof(uv_connect_t));
      cn_wrap->data = baton;
      uv_pipe_connect(cn_wrap, sock, path, on_client_connection);
      context_init((uv_stream_t *)sock, s, 1);
      args.GetReturnValue().Set(Integer::New(isolate, 0));
      return;
    }
  }

  void Socket::onHeaders(const v8::FunctionCallbackInfo<v8::Value>& args) {
    Isolate* isolate = args.GetIsolate();
    Socket* s = ObjectWrap::Unwrap<Socket>(args.Holder());
    if(args[0]->IsFunction()) {
      Local<Function> onHeaders = Local<Function>::Cast(args[0]);
      s->_onHeaders.Reset(isolate, onHeaders);
      s->callbacks.onHeaders = 1;
    }
  }

  void Socket::onBody(const v8::FunctionCallbackInfo<v8::Value>& args) {
    Isolate* isolate = args.GetIsolate();
    Socket* s = ObjectWrap::Unwrap<Socket>(args.Holder());
    if(args[0]->IsFunction()) {
      Local<Function> onBody = Local<Function>::Cast(args[0]);
      s->_onBody.Reset(isolate, onBody);
      s->callbacks.onBody = 1;
    }
  }

  void Socket::onRequest(const v8::FunctionCallbackInfo<v8::Value>& args) {
    Isolate* isolate = args.GetIsolate();
    Socket* s = ObjectWrap::Unwrap<Socket>(args.Holder());
    if(args[0]->IsFunction()) {
      Local<Function> onRequest = Local<Function>::Cast(args[0]);
      s->_onRequest.Reset(isolate, onRequest);
      s->callbacks.onRequest = 1;
    }
  }

  void Socket::onResponse(const v8::FunctionCallbackInfo<v8::Value>& args) {
    Isolate* isolate = args.GetIsolate();
    Socket* s = ObjectWrap::Unwrap<Socket>(args.Holder());
    if(args[0]->IsFunction()) {
      Local<Function> onResponse = Local<Function>::Cast(args[0]);
      s->_onResponse.Reset(isolate, onResponse);
      s->callbacks.onResponse = 1;
    }
  }

  void Socket::onClose(const v8::FunctionCallbackInfo<v8::Value>& args) {
    Isolate* isolate = args.GetIsolate();
    Socket* s = ObjectWrap::Unwrap<Socket>(args.Holder());
    if(args[0]->IsFunction()) {
      Local<Function> onClose = Local<Function>::Cast(args[0]);
      s->_onClose.Reset(isolate, onClose);
      s->callbacks.onClose = 1;
    }
  }

  void Socket::onWrite(const v8::FunctionCallbackInfo<v8::Value>& args) {
    Isolate* isolate = args.GetIsolate();
    Socket* s = ObjectWrap::Unwrap<Socket>(args.Holder());
    if(args[0]->IsFunction()) {
      Local<Function> onWrite = Local<Function>::Cast(args[0]);
      s->_onWrite.Reset(isolate, onWrite);
      s->callbacks.onWrite = 1;
    }
  }

  void Socket::onData(const v8::FunctionCallbackInfo<v8::Value>& args) {
    Isolate* isolate = args.GetIsolate();
    Socket* s = ObjectWrap::Unwrap<Socket>(args.Holder());
    if(args[0]->IsFunction()) {
      Local<Function> onData = Local<Function>::Cast(args[0]);
      s->_onData.Reset(isolate, onData);
      s->callbacks.onData = 1;
    }
  }

  void Socket::onError(const v8::FunctionCallbackInfo<v8::Value>& args) {
    Isolate* isolate = args.GetIsolate();
    Socket* s = ObjectWrap::Unwrap<Socket>(args.Holder());
    if(args[0]->IsFunction()) {
      Local<Function> onError = Local<Function>::Cast(args[0]);
      s->_onError.Reset(isolate, onError);
      s->callbacks.onError = 1;
    }
  }

  void Socket::onConnect(const v8::FunctionCallbackInfo<v8::Value>& args) {
    Isolate* isolate = args.GetIsolate();
    Socket* s = ObjectWrap::Unwrap<Socket>(args.Holder());
    if(args[0]->IsFunction()) {
      Local<Function> onConnect = Local<Function>::Cast(args[0]);
      s->_onConnect.Reset(isolate, onConnect);
      s->callbacks.onConnect = 1;
    }
  }

  void Socket::Listen(const FunctionCallbackInfo<Value>& args) {
    Isolate* isolate = args.GetIsolate();
    Socket* s = ObjectWrap::Unwrap<Socket>(args.Holder());
    if(args[0]->IsNumber()) { // we have been passed a socket handle that has already been bound
      int fd = static_cast<int>(args[0]->IntegerValue());
      if(s->socktype == TCP) {
        uv_tcp_t* sock = (uv_tcp_t*)malloc(sizeof(uv_tcp_t));
        sock->data = s;
        baton_t* baton = (baton_t*)malloc(sizeof(baton_t));
        baton->callback = (void*)onNewConnection;
        baton->object = sock->data;
        sock->data = baton;
        int status = uv_tcp_init(uv_default_loop(), sock);
        if (status) {
          args.GetReturnValue().Set(Integer::New(isolate, status));
          return;
        }
        status = uv_tcp_open(sock, fd);
        if (status) {
          args.GetReturnValue().Set(Integer::New(isolate, status));
          return;
        }
        status = uv_listen((uv_stream_t*)sock, SOMAXCONN, on_connection);
        if (status) {
          args.GetReturnValue().Set(Integer::New(isolate, status));
          return;
        }
      }
      else if(s->socktype == UNIX) {
        uv_pipe_t* sock = (uv_pipe_t*)malloc(sizeof(uv_pipe_t));
        sock->data = s;
        baton_t* baton = (baton_t*)malloc(sizeof(baton_t));
        baton->callback = (void*)onNewConnection;
        baton->object = sock->data;
        sock->data = baton;
        int status = uv_pipe_init(uv_default_loop(), sock, 0);
        if (status) {
          args.GetReturnValue().Set(Integer::New(isolate, status));
          return;
        }
        status = uv_pipe_open(sock, fd);
        if (status) {
          args.GetReturnValue().Set(Integer::New(isolate, status));
          return;
        }
        status = uv_listen((uv_stream_t*)sock, SOMAXCONN, on_connection);
        if (status) {
          args.GetReturnValue().Set(Integer::New(isolate, status));
          return;
        }
      }
      else {
        // error
      }
    }
    else if(s->socktype == TCP) { // we are getting a port so must be TCP
      const unsigned int port = args[1]->IntegerValue();
      uv_tcp_t* sock = (uv_tcp_t*)malloc(sizeof(uv_tcp_t));
      sock->data = s;
      v8::String::Utf8Value utf8Value(args[0]);
      char* ip_address = (*utf8Value);
      struct sockaddr_in addr;
      uv_ip4_addr(ip_address, port, &addr);
      baton_t* baton = (baton_t*)malloc(sizeof(baton_t));
      baton->callback = (void*)onNewConnection;
      baton->object = sock->data;
      sock->data = baton;
      int status = uv_tcp_init(uv_default_loop(), sock);
      if (status) {
        args.GetReturnValue().Set(Integer::New(isolate, status));
        return;
      }
      status = uv_tcp_bind(sock, (const struct sockaddr*) &addr, 0);
      if (status) {
        args.GetReturnValue().Set(Integer::New(isolate, status));
        return;
      }
      status = uv_listen((uv_stream_t*)sock, SOMAXCONN, on_connection);
      if (status) {
        args.GetReturnValue().Set(Integer::New(isolate, status));
        return;
      }
      s->_stream = (uv_stream_t*)sock;
    }
    else if(s->socktype == UNIX) { // use first argument as path to domain socket
      v8::String::Utf8Value utf8Value(args[0]);
      char* path = (*utf8Value);
      uv_pipe_t* sock = (uv_pipe_t*)malloc(sizeof(uv_pipe_t));
      sock->data = s;
      baton_t* baton = (baton_t*)malloc(sizeof(baton_t));
      baton->callback = (void*)onNewConnection;
      baton->object = sock->data;
      sock->data = baton;
      int status = uv_pipe_init(uv_default_loop(), sock, 0);
      if (status) {
        args.GetReturnValue().Set(Integer::New(isolate, status));
        return;
      }
      status = uv_pipe_bind(sock, path);
      if (status) {
        args.GetReturnValue().Set(Integer::New(isolate, status));
        return;
      }
      status = uv_listen((uv_stream_t*)sock, SOMAXCONN, on_connection);
      if (status) {
        args.GetReturnValue().Set(Integer::New(isolate, status));
        return;
      }
      s->_stream = (uv_stream_t*)sock;
    }
    else {
      // error
    }
    args.GetReturnValue().Set(Integer::New(isolate, 0));
  }

  void Socket::Bind(const FunctionCallbackInfo<Value>& args) {
    Isolate* isolate = args.GetIsolate();
    Socket* s = ObjectWrap::Unwrap<Socket>(args.Holder());
    if(s->socktype == TCP) {
      const unsigned int port = args[1]->IntegerValue();
      uv_tcp_t* sock = (uv_tcp_t*)malloc(sizeof(uv_tcp_t));
      sock->data = s;
      v8::String::Utf8Value utf8Value(args[0]);
      char* ip_address = (*utf8Value);
      struct sockaddr_in addr;
      uv_ip4_addr(ip_address, port, &addr);
      baton_t* baton = (baton_t*)malloc(sizeof(baton_t));
      baton->callback = (void*)onNewConnection;
      baton->object = sock->data;
      sock->data = baton;
      int status = uv_tcp_init(uv_default_loop(), sock);
      if (status) {
        args.GetReturnValue().Set(Integer::New(isolate, status));
        return;
      }
      status = uv_tcp_bind(sock, (const struct sockaddr*) &addr, 0);
      if (status) {
        args.GetReturnValue().Set(Integer::New(isolate, status));
        return;
      }
    }
    else if(s->socktype == UNIX) { // it is a domain socket
      v8::String::Utf8Value str(args[0]);
      uv_pipe_t* sock = (uv_pipe_t*)malloc(sizeof(uv_pipe_t));
      sock->data = s;
      baton_t* baton = (baton_t*)malloc(sizeof(baton_t));
      baton->callback = (void*)onNewConnection;
      baton->object = sock->data;
      sock->data = baton;
      int status = uv_pipe_init(uv_default_loop(), sock, 0);
      if (status) {
        args.GetReturnValue().Set(Integer::New(isolate, status));
        return;
      }
      status = uv_pipe_bind(sock, *str);
      if (status) {
        args.GetReturnValue().Set(Integer::New(isolate, status));
        return;
      }
    }
    else {
      // error
    }
    args.GetReturnValue().Set(Integer::New(isolate, 0));
  }

}