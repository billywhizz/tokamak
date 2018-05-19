#include <node.h>
#include "tinysocket.h"

namespace tokamak {

using v8::FunctionCallbackInfo;
using v8::Isolate;
using v8::Local;
using v8::Object;
using v8::String;
using v8::Value;

void CreateSocket(const FunctionCallbackInfo<Value>& args) {
  Socket::NewInstance(args);
}


void InitAll(Local<Object> exports, Local<Object> module) {
  Socket::Init(exports->GetIsolate());
  NODE_SET_METHOD(exports, "createSocket", CreateSocket);
}

NODE_MODULE(tokamak, InitAll)

}