# Jacquard/Tokamak

- A small and fast library for doing sockets in node.js

## Build

```
npm run build
```

## Install

```
npm install jacquard
```

## Documentation

[TODO]


## Testing

```
npm install --dev-only
npm run test
```

## Features

### Available

- small fast tcp and http library for node.js
- zero heap allocations under load
- low latency
- built in cluster mode for child workers
- built in tcp proxy for minimal copy socket proxying
- Unix Domain Sockets/Pipes
- TCP
- HTTP Pipelined requests

### Planned/To Decide

- SSL wrapper for socket
- Low overheader router for api developers
- Node.js/Express/Connect middleware compatibility
- HTTP/2 support
- Websocket support
- "ws" module compatibility layer
- API Gateway with Plugins
- Metrics
- Tracing

## Goals

- to be small, fast and low latency
- to be robust and safe under load/attack
- to be able to serve as many API requests as nginx with lua
- to be near top of techempower json and plaintext benchmarks
- to be able to handle load of a busy API gateway when proxying to backends
- to do everything kong can but better/faster and native to JS
- to be easy to develop plugins and middlewares for

## API

### Socket

#### Methods

- Socket.listen
- Socket.connect
- Socket.bind
- Socket.close
- Socket.pull
- Socket.push
- Socket.write
- Socket.writeText
- Socket.setup
- Socket.setNoDelay
- Socket.pause
- Socket.resume
- Socket.setKeepAlive
- Socket.proxy
- Socket.remoteAddress

#### Events

- Socket.onConnect
- Socket.onHeaders
- Socket.onBody
- Socket.onRequest
- Socket.onResponse
- Socket.onClose
- Socket.onWrite
- Socket.onData
- Socket.onError

## Benchmarks

### Normal (Non-Pipelined) HTTP

```
node examples/fast
docker run -it --rm williamyeh/wrk -c 200 -t 2 -d 20 http://172.17.0.1:3000/
```

- 175k RPS on single Core i7
- 36 MB RSS with no gc pauses as no new garbage created
- Avg Latency 1.14ms, Max Latency 9.04ms
- CPU pegged at 100%

### Normal (Non-Pipelined) HTTP

```
node examples/fast
docker run -it -v $(pwd):/foo --rm williamyeh/wrk -s /foo/bench.lua -c 2000 -t 2 -d 20 http://172.17.0.1:3000/
```

- 552k RPS on single Core i7
- 100 MB RSS with no gc pauses as no new garbage created
- Avg Latency 25.19ms, Max Latency 327ms
- CPU pegged at 100%
