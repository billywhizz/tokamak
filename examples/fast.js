const { createSocket } = require('../')

const READ_BUFFER_SIZE = 4096
const WRITE_BUFFER_SIZE = 4096
const r200 = 'HTTP/1.1 200 OK\r\nServer: foo\r\nContent-Length: 0\r\n\r\n'
const size200 = r200.length
const contexts = {}

const sock = createSocket(1, 0)

sock.onConnect(fd => {
	if (!contexts[fd]) {
		const context = {
			major: 1,
			minor: 1,
			method: 0,
			upgrade: 0,
			keepalive: false,
			headerCount: 0,
			url: '',
			in: Buffer.alloc(READ_BUFFER_SIZE),
			out: Buffer.alloc(WRITE_BUFFER_SIZE),
			headers: '0'.repeat(20).split('').map(() => ['', ''])
		}
		contexts[fd] = context
		sock.setup(fd, context.in, context.out, context.headers)
	}
	sock.setNoDelay(fd, false)
	sock.push(fd, r200, 0)
})

sock.onHeaders(fd => {
	sock.write(fd, 0, size200)
})

sock.listen('0.0.0.0', 3000)
